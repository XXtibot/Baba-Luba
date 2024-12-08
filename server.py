import os
import ssl
import socket
import threading
import logging
import queue
from tkinter import Tk, Toplevel, Text, Entry, Button, filedialog, Scrollbar, END, messagebox, Label, StringVar
from tkinter.ttk import Progressbar

class ChatWindow:
    def __init__(self, master, conn, addr, logger, server_gui):
    
        self.master = master
        self.conn = conn
        self.addr = addr
        self.logger = logger
        self.server_gui = server_gui
        self.running = True
        self.lock = threading.Lock()

      
        self.queue = queue.Queue()

       
        self.window = Toplevel(master)
        self.window.title(f"Чат с {addr}")
        self.window.protocol("WM_DELETE_WINDOW", self.close_window)

    
        self.status_var = StringVar(value="Онлайн")
        self.status_label = Label(self.window, textvariable=self.status_var, fg="green")
        self.status_label.grid(row=0, column=0, columnspan=3, pady=5)

        
        self.text_area = Text(self.window, state="disabled", wrap="word", height=20, width=60)
        self.text_area.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

        
        scrollbar = Scrollbar(self.window, command=self.text_area.yview)
        self.text_area["yscrollcommand"] = scrollbar.set
        scrollbar.grid(row=1, column=3, sticky="ns")

        
        self.entry = Entry(self.window, width=50)
        self.entry.grid(row=2, column=0, padx=10, pady=10)

        
        self.send_button = Button(self.window, text="Отправить", command=self.send_message)
        self.send_button.grid(row=2, column=1, padx=5)

        
        self.file_button = Button(self.window, text="файл", command=self.send_file)
        self.file_button.grid(row=2, column=2, padx=5)

        
        self.send_progress = Progressbar(self.window, orient="horizontal", length=300, mode="determinate")
        self.send_progress.grid(row=3, column=0, columnspan=3, padx=10, pady=5)

        
        self.download_button = Button(self.window, text="Скачать файл", command=self.download_file, state="disabled")
        self.download_button.grid(row=4, column=0, columnspan=3, pady=5)

        
        self.receive_progress = Progressbar(self.window, orient="horizontal", length=300, mode="determinate")
        self.receive_progress.grid(row=5, column=0, columnspan=3, padx=10, pady=5)

        
        self.chat_history_file = f"chat_history_{self.addr[0]}_{self.addr[1]}.txt"

        
        self.received_file = None
        self.received_file_name = None
        self.received_file_size = 0

        
        self.receive_thread = threading.Thread(target=self.receive_data, daemon=True)
        self.receive_thread.start()

        
        self.window.after(100, self.process_queue)

    def append_message(self, message):
        
        self.text_area.config(state="normal")
        self.text_area.insert(END, f"{message}\n")
        self.text_area.config(state="disabled")
        self.text_area.see(END)

        
        with open(self.chat_history_file, "a", encoding="utf-8") as file:
            file.write(f"{message}\n")

        self.logger.info(f"{self.addr}: {message}")

    def send_message(self):
        
        message = self.entry.get()
        if message and self.conn:
            try:
                with self.lock:
                    
                    formatted_message = f"MSG:{message}\n".encode()
                    self.conn.sendall(formatted_message)
                self.append_message(f"Вы: {message}")
                self.entry.delete(0, END)
                self.logger.info(f"Sent message to {self.addr}: {message}")
            except Exception as e:
                error_msg = f"Error sending message: {e}"
                self.append_message(error_msg)
                self.logger.error(error_msg)

    def send_file(self):
        
        file_path = filedialog.askopenfilename()
        if file_path and self.conn:
            try:
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                
                file_header = f"FILE:{file_name}:{file_size}\n".encode()
                with self.lock:
                    self.conn.sendall(file_header)
                    self.logger.info(f"Отправка файла к {self.addr}: {file_name} ({file_size} bytes)")

                    with open(file_path, "rb") as f:
                        sent_bytes = 0
                        while True:
                            chunk = f.read(4096)
                            if not chunk:
                                break
                            self.conn.sendall(chunk)
                            sent_bytes += len(chunk)
                            progress = (sent_bytes / file_size) * 100
                            self.send_progress['value'] = progress
                            self.window.update_idletasks()

                self.append_message(f"Вы отпаравили файл: {file_name}")
                self.logger.info(f"Отправлен файл {self.addr}: {file_name} ({file_size} bytes)")
                self.send_progress['value'] = 0  
            except Exception as e:
                error_msg = f"Ошибка отпарвки файла: {e}"
                self.append_message(error_msg)
                self.logger.error(error_msg)

    def receive_data(self):
        
        self.buffer = b''
        self.state = 'READY'
        self.expected_file_size = 0
        self.received_file = None
        self.received_file_name = ''
        self.file_data = b''

        try:
            while self.running:
                data = self.conn.recv(4096)
                if not data:
                    self.queue.put("Клиент вышел.")
                    break  
                
                self.buffer += data

                while True:
                    if self.state == 'READY':
                        
                        if b'\n' in self.buffer:
                            line, self.buffer = self.buffer.split(b'\n', 1)
                            line = line.decode()
                            if line.startswith("MSG:"):
                                
                                message = line[4:]
                                self.queue.put(f"Клиент: {message}")
                                self.logger.info(f"Получено сообщение от клиента: {message}")
                            elif line.startswith("FILE:"):
                              
                                try:
                                    parts = line.split(':', 2)
                                    if len(parts) == 3:
                                        _, filename, size_str = parts
                                        self.expected_file_size = int(size_str)
                                        self.received_file_name = filename
                                        self.received_file = b""
                                        self.file_data = b""
                                        self.logger.info(f"Получение файла: {filename} ({self.expected_file_size} байтов)")
                                        self.queue.put(f"Получение файла: {filename} ({self.expected_file_size} байтов)")
                                        self.receive_progress['value'] = 0
                                        self.state = 'RECEIVING_FILE'
                                    else:
                                        self.queue.put("Invalid file header received.")
                                        self.logger.error(f"Invalid file header received: {line}")
                                except Exception as e:
                                    error_msg = f"Error parsing file header: {e}"
                                    self.queue.put(error_msg)
                                    self.logger.error(error_msg)
                            else:
                                
                                self.queue.put(f"Клиент: {line}")
                                self.logger.info(f"Получено от клиента: {line}")
                        else:
                            
                            break

                    elif self.state == 'RECEIVING_FILE':
                        
                        remaining_bytes = self.expected_file_size - len(self.file_data)
                        
                        to_read = min(remaining_bytes, len(self.buffer))
                        self.file_data += self.buffer[:to_read]
                        self.buffer = self.buffer[to_read:]

                        
                        progress = (len(self.file_data) / self.expected_file_size) * 100
                        self.receive_progress['value'] = progress
                        self.window.update_idletasks()

                        if len(self.file_data) == self.expected_file_size:
                            
                            self.received_file = self.file_data
                            self.queue.put(f"Файл получен: {self.received_file_name}")
                            self.logger.info(f"Файл получен от клиента: {self.received_file_name}")
                            self.queue.put("enable_download")
                            self.state = 'READY'
                            self.file_data = b""
                            self.expected_file_size = 0
                            
                            self.receive_progress['value'] = 0
                        elif len(self.buffer) == 0:
                            
                            break 
        except Exception as e:
            if self.running:
                error_msg = f"Ошибка: {e}"
                self.queue.put(error_msg)
                self.logger.error(error_msg)
        finally:
            self.queue.put("Клиент вышел.")
            self.conn.close()

    def download_file(self):
        
        if self.received_file is None:
            self.append_message("нету полученных файлов.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension="", initialfile=self.received_file_name)
        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.received_file)
                self.append_message(f"Файл сохранен в: {file_path}")
                self.download_button.config(state="disabled")  
                self.logger.info(f"файл от клиента сохранен в: {file_path}")
           
                self.received_file = None
                self.received_file_name = ''
            except Exception as e:
                error_msg = f"Ошибка сохранения: {e}"
                self.append_message(error_msg)
                self.logger.error(error_msg)
                messagebox.showerror("Ошибка", error_msg)

    def process_queue(self):
        
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg.startswith("Отключен"):
                    self.status_var.set("Отключен")
                    self.status_label.config(fg="red")
                    self.entry.config(state="disabled")
                    self.send_button.config(state="disabled")
                    self.file_button.config(state="disabled")
                elif msg == "enable_download":
                    self.download_button.config(state="normal")
                elif msg.startswith("Клиент:"):
                    self.append_message(msg)
                else:
                    
                    self.append_message(msg)
        except queue.Empty:
            pass
        if self.running:
            self.window.after(100, self.process_queue)

    def close_window(self):
     
        self.running = False
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
        except Exception:
            pass
        self.window.destroy()
        self.server_gui.remove_client(self.addr)
        self.logger.info(f"Chat window closed for {self.addr}")

class SecureChatServerGUI:
    def __init__(self, root, host, port, certfile, keyfile):
        self.root = root
        self.root.title("Баба Люба")
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.running = True
        self.lock = threading.Lock()
        self.client_handlers = {}  

       
        logging.basicConfig(
            filename='server.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger()

        self.logger.info("Server GUI initialized.")

       
        self.status_label = Label(self.root, text=f"Server running on {self.host}:{self.port}")
        self.status_label.grid(row=0, column=0, columnspan=2, padx=10, pady=5)

        
        self.online_label = Label(self.root, text="Онлайн клиенты:")
        self.online_label.grid(row=1, column=0, padx=10, pady=5, sticky='w')

        self.online_list = Text(self.root, state="disabled", height=10, width=60)
        self.online_list.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

       
        self.root.protocol("WM_DELETE_WINDOW", self.close_application)

       
        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()

    def append_server_message(self, message):
       
        self.logger.info(f"Сервер: {message}")
        self.online_list.config(state="normal")
        self.online_list.insert(END, f"{message}\n")
        self.online_list.config(state="disabled")
        self.online_list.see(END)

    def start_server(self):
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certfile, self.keyfile)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind((self.host, self.port))
            server.listen(5)  
            self.append_server_message(f"Сервер стартовал {self.host}:{self.port}")
            self.logger.info(f"Сервер слушает {self.host}:{self.port}")

            while self.running:
                try:
                    raw_conn, addr = server.accept()
                    ssl_conn = context.wrap_socket(raw_conn, server_side=True)
                    self.append_server_message(f"Клиент подключился: {addr}")
                    self.logger.info(f"Клиент подключился: {addr}")

                    
                    chat_window = ChatWindow(self.root, ssl_conn, addr, self.logger, self)
                    self.client_handlers[addr] = chat_window
                    self.update_online_clients()
                except Exception as e:
                    if self.running:
                        error_msg = f"Ошибка принятия подключения: {e}"
                        self.append_server_message(error_msg)
                        self.logger.error(error_msg)

    def remove_client(self, addr):
        
        if addr in self.client_handlers:
            del self.client_handlers[addr]
            self.append_server_message(f"Клиент отключился: {addr}")
            self.update_online_clients()

    def update_online_clients(self):
        
        self.online_list.config(state="normal")
        self.online_list.delete(1.0, END)
        if self.client_handlers:
            for addr in self.client_handlers:
                self.online_list.insert(END, f"{addr}\n")
        else:
            self.online_list.insert(END, "Нет подключенных клиентов.\n")
        self.online_list.config(state="disabled")

    def close_application(self):
        
        self.running = False
        self.append_server_message("Shutting down server...")
        self.logger.info("Shutting down server.")

       
        for addr, handler in list(self.client_handlers.items()):
            handler.close_window()

        self.root.destroy()
        self.logger.info("Server shut down.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Секретный чат)")
    parser.add_argument("--host", default="0.0.0.0", help="IP address to bind the server (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5555, help="Port to bind the server (default: 5555)")
    parser.add_argument("--certfile", default="cert.pem", help="Path to the SSL certificate")
    parser.add_argument("--keyfile", default="key.pem", help="Path to the SSL private key")
    args = parser.parse_args()

    # Ensure certificate and key files exist
    if not os.path.exists(args.certfile):
        raise FileNotFoundError(f"Certificate file not found: {args.certfile}")
    if not os.path.exists(args.keyfile):
        raise FileNotFoundError(f"Key file not found: {args.keyfile}")

    root = Tk()
    app = SecureChatServerGUI(root, host=args.host, port=args.port,
                              certfile=args.certfile, keyfile=args.keyfile)
    root.mainloop()