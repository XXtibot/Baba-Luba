import os
import ssl
import socket
import threading
import logging
import queue
from tkinter import (
    Tk, Text, Entry, Button, filedialog, Scrollbar, END, messagebox,
    Label, StringVar
)
from tkinter.ttk import Progressbar

class SecureChatClientGUI:
    def __init__(self, root, host, port, certfile):
        self.root = root
        self.root.title("Баба Люба ")
        self.host = host
        self.port = port
        self.certfile = certfile
        self.conn = None
        self.running = True
        self.lock = threading.Lock()
        self.received_file = None  
        self.received_file_name = None

        
        logging.basicConfig(
            filename='client.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger()

       
        self.queue = queue.Queue()

        
        self.status_var = StringVar(value="Disconnected")
        self.status_label = Label(self.root, textvariable=self.status_var, fg="red")
        self.status_label.grid(row=0, column=0, columnspan=3, pady=5)

       
        self.text_area = Text(self.root, state="disabled", wrap="word", height=20, width=60)
        self.text_area.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

       
        scrollbar = Scrollbar(self.root, command=self.text_area.yview)
        self.text_area["yscrollcommand"] = scrollbar.set
        scrollbar.grid(row=1, column=3, sticky="ns")

        
        self.entry = Entry(self.root, width=50)
        self.entry.grid(row=2, column=0, padx=10, pady=10)

        
        self.send_button = Button(self.root, text="Отправить", command=self.send_message)
        self.send_button.grid(row=2, column=1, padx=5)

        
        self.file_button = Button(self.root, text="Файл", command=self.send_file)
        self.file_button.grid(row=2, column=2, padx=5)

        
        self.send_progress = Progressbar(self.root, orient="horizontal", length=300, mode="determinate")
        self.send_progress.grid(row=3, column=0, columnspan=3, padx=10, pady=5)

        
        self.download_button = Button(self.root, text="Скачать файл", command=self.download_file, state="disabled")
        self.download_button.grid(row=4, column=0, columnspan=3, pady=5)

       
        self.receive_progress = Progressbar(self.root, orient="horizontal", length=300, mode="determinate")
        self.receive_progress.grid(row=5, column=0, columnspan=3, padx=10, pady=5)

        
        self.chat_history_file = "chat_history.txt"

       
        self.client_thread = threading.Thread(target=self.start_client, daemon=True)
        self.client_thread.start()

        
        self.root.protocol("WM_DELETE_WINDOW", self.close_application)

       
        self.root.after(100, self.process_queue)

    def append_message(self, message):
    
        self.text_area.config(state="normal")
        self.text_area.insert(END, f"{message}\n")
        self.text_area.config(state="disabled")
        self.text_area.see(END)

        
        with open(self.chat_history_file, "a", encoding="utf-8") as file:
            file.write(f"{message}\n")

    def send_message(self):
        
        message = self.entry.get()
        if message and self.conn:
            try:
                with self.lock:
                    
                    formatted_message = f"MSG:{message}\n".encode()
                    self.conn.sendall(formatted_message)
                self.append_message(f"Вы: {message}")
                self.entry.delete(0, END)
                self.logger.info(f"Отправить сообщени серверу: {message}")
            except Exception as e:
                error_msg = f"Ошибка отпарвки сообщения: {e}"
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
                    self.logger.info(f"Отправка файла к серверу: {file_name} ({file_size} байтов)")

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
                            self.root.update_idletasks()

                self.append_message(f"Вы отправили файл: {file_name}")
                self.logger.info(f"Файл отпарвлен к серверу: {file_name} ({file_size} байтов)")
                self.send_progress['value'] = 0 
            except Exception as e:
                error_msg = f"Ошибка отправки: {e}"
                self.append_message(error_msg)
                self.logger.error(error_msg)

    def start_client(self):
        
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        try:
            context.load_verify_locations(self.certfile)
        except Exception as e:
            self.queue.put(f"Error loading certificate: {e}")
            messagebox.showerror("Error", f"Error loading certificate: {e}")
            return

        try:
            
            raw_socket = socket.create_connection((self.host, self.port))
            self.conn = context.wrap_socket(raw_socket, server_hostname=self.host)
            self.logger.info("Подключен к серверу.")
            self.queue.put("Подключен к серверу.")

            # Start receiving data
            self.receive_data_thread = threading.Thread(target=self.receive_data, daemon=True)
            self.receive_data_thread.start()
        except Exception as e:
            error_msg = f"Ошибка соединения: {e}"
            self.queue.put(error_msg)
            self.logger.error(error_msg)
            self.queue.put("Отключение.")
            messagebox.showerror("Ошибка соединения", error_msg)

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
                    self.queue.put("Отключение.")
                    break  
                
                self.buffer += data

                while True:
                    if self.state == 'READY':
                        
                        if b'\n' in self.buffer:
                            line, self.buffer = self.buffer.split(b'\n', 1)
                            line = line.decode()
                            if line.startswith("MSG:"):
                                # Handle incoming message
                                message = line[4:]
                                self.queue.put(f"Сервер: {message}")
                                self.logger.info(f"Получено сообщение от сервера: {message}")
                            elif line.startswith("FILE:"):
                               
                                try:
                                    parts = line.split(':', 2)
                                    if len(parts) == 3:
                                        _, filename, size_str = parts
                                        self.expected_file_size = int(size_str)
                                        self.received_file_name = filename
                                        self.received_file = b""
                                        self.file_data = b""
                                        self.logger.info(f"Получение файла: {filename} ({self.expected_file_size} bytes)")
                                        self.queue.put(f"Получен файл: {filename} ({self.expected_file_size} bytes)")
                                        self.receive_progress['value'] = 0
                                        self.state = 'RECEIVING_FILE'
                                    else:
                                        self.queue.put("Ошибка.")
                                        self.logger.error(f"Invalid file header received: {line}")
                                except Exception as e:
                                    error_msg = f"Error parsing file header: {e}"
                                    self.queue.put(error_msg)
                                    self.logger.error(error_msg)
                            else:
                                
                                self.queue.put(f"Сервер: {line}")
                                self.logger.info(f"Получено от сервера: {line}")
                        else:
                           
                            break  

                    elif self.state == 'RECEIVING_FILE':
                        
                        remaining_bytes = self.expected_file_size - len(self.file_data)
                       
                        to_read = min(remaining_bytes, len(self.buffer))
                        self.file_data += self.buffer[:to_read]
                        self.buffer = self.buffer[to_read:]

                        # Update progress bar
                        progress = (len(self.file_data) / self.expected_file_size) * 100
                        self.receive_progress['value'] = progress
                        self.root.update_idletasks()

                        if len(self.file_data) == self.expected_file_size:
                            # File received completely
                            self.received_file = self.file_data
                            self.queue.put(f"Файл получен: {self.received_file_name}")
                            self.logger.info(f"Получен файл от сервера: {self.received_file_name}")
                            self.queue.put("enable_download")
                            self.state = 'READY'
                            self.file_data = b""
                            self.expected_file_size = 0
                            
                            self.receive_progress['value'] = 0
                        elif len(self.buffer) == 0:
                            
                            break  
        except Exception as e:
            error_msg = f"Ошибка получении данных: {e}"
            self.queue.put(error_msg)
            self.logger.error(error_msg)
        finally:
            self.queue.put("Отключение от сервера.")
            self.conn.close()

    def download_file(self):
        
        if self.received_file is None:
            self.append_message("Нет файлов готовых к получению.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension="", initialfile=self.received_file_name)
        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(self.received_file)
                self.append_message(f"Файл сохранен в: {file_path}")
                self.download_button.config(state="disabled")  
                self.logger.info(f"Файл от сервера сохранен в: {file_path}")
                
                self.received_file = None
                self.received_file_name = ''
            except Exception as e:
                error_msg = f"Ошибка скачивания: {e}"
                self.append_message(error_msg)
                self.logger.error(error_msg)
                messagebox.showerror("Ошибка", error_msg)

    def process_queue(self):
        
        try:
            while True:
                msg = self.queue.get_nowait()
                if msg.startswith("Подключен к серверу."):
                    self.status_var.set("Онлайн")
                    self.status_label.config(fg="green")
                    self.entry.config(state="normal")
                    self.send_button.config(state="normal")
                    self.file_button.config(state="normal")
                elif msg.startswith("Отключен"):
                    self.status_var.set("Отключен")
                    self.status_label.config(fg="red")
                    self.entry.config(state="disabled")
                    self.send_button.config(state="disabled")
                    self.file_button.config(state="disabled")
                elif msg == "enable_download":
                    self.download_button.config(state="normal")
                elif msg.startswith("Сервер:"):
                    self.append_message(msg)
                else:
                    
                    self.append_message(msg)
        except queue.Empty:
            pass
        if self.running:
            self.root.after(100, self.process_queue)

    def close_application(self):
        
        self.running = False
        if self.conn:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
            except Exception:
                pass
        self.root.destroy()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Секретный чат)")
    parser.add_argument("--host", default="127.0.0.1", help="Server IP address to connect to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5555, help="Server port to connect to (default: 5555)")
    parser.add_argument("--certfile", default="cert.pem", help="Path to the SSL certificate")
    args = parser.parse_args()

    # Ensure certificate file exists
    if not os.path.exists(args.certfile):
        raise FileNotFoundError(f"Certificate file not found: {args.certfile}")

    root = Tk()
    app = SecureChatClientGUI(root, host=args.host, port=args.port, certfile=args.certfile)
    root.mainloop()