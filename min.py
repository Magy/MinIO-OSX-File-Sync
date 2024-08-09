import os
import json
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from datetime import datetime
import logging
import subprocess
import queue
import hashlib
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
from pystray import MenuItem as item
from PIL import Image, ImageTk

# Logging configuration
logging.basicConfig(filename='sync_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Logging functions
def log_info(message):
    logging.info(message)
    print(message)

def log_error(message):
    logging.error(message)
    print(message)

# Load configuration from JSON file
CONFIG_FILE = "config.json"
MESSAGES_FILE = "messages.json"
config = {}
messages = {}

def load_config():
    global config
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as config_file:
                config = json.load(config_file)
    except Exception as e:
        log_error(f"Error loading configuration: {e}")
        raise

def load_messages(language='en'):
    global messages
    try:
        if os.path.exists(MESSAGES_FILE):
            with open(MESSAGES_FILE, 'r') as file:
                messages = json.load(file)
        messages = messages.get(language, messages['en'])
    except Exception as e:
        log_error(f"Error loading messages: {e}")
        raise

load_config()
language = config.get('language', 'en')
load_messages(language)

# Retrieve credentials and configurations from the config file
MINIO_ENDPOINT = config.get("MINIO_ENDPOINT")
MINIO_ACCESS_KEY = config.get("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = config.get("MINIO_SECRET_KEY")
MINIO_BUCKET = config.get("MINIO_BUCKET")
CHECK_INTERVAL = int(config.get("CHECK_INTERVAL", 60))  # Convert to integer

# Check that all credentials are present
if not all([MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_BUCKET]):
    log_error(messages["invalid_credentials"])
    raise ValueError(messages["invalid_credentials"])

# Pause/resume control variable
is_paused = threading.Event()
is_paused.set()  # Start with synchronization active

# Queue for GUI updates
gui_queue = queue.Queue()

# Variable for server connection control
is_connected = threading.Event()
is_connected.clear()

# Variables to track transferred data
uploaded_data = 0
downloaded_data = 0

# Dictionary to keep track of file hashes and their names
file_hashes = {}

# Set to keep track of files being uploaded
uploading_files = set()

def calculate_file_hash(file_path, hash_algorithm='sha256'):
    hash_algo = hashlib.new(hash_algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()

# Folder monitoring
class Watcher:
    def __init__(self, directory_to_watch):
        self.observer = Observer()
        self.directory_to_watch = directory_to_watch

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.directory_to_watch, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
            log_info("Observer Stopped")
        self.observer.join()

class Handler(FileSystemEventHandler):
    def process(self, event):
        if event.is_directory:
            return None
        elif event.event_type in ('created', 'modified'):
            if not os.path.basename(event.src_path).startswith('.') and not os.path.basename(event.src_path) == ".DS_Store":
                if event.src_path not in uploading_files:
                    uploading_files.add(event.src_path)
                    log_info(f"Start upload for {event.src_path}")
                    threading.Thread(target=upload_file_to_minio, args=(event.src_path,)).start()
        elif event.event_type == 'deleted':
            relative_path = os.path.relpath(event.src_path, config.get("directory_to_watch"))
            file_name = relative_path.replace(os.sep, "/")
            delete_file_from_minio(file_name)
        elif event.event_type == 'moved':
            old_relative_path = os.path.relpath(event.src_path, config.get("directory_to_watch"))
            old_file_name = old_relative_path.replace(os.sep, "/")
            new_relative_path = os.path.relpath(event.dest_path, config.get("directory_to_watch"))
            new_file_name = new_relative_path.replace(os.sep, "/")
            move_file_on_minio(old_file_name, new_file_name)

    def on_created(self, event):
        self.process(event)

    def on_modified(self, event):
        self.process(event)
    
    def on_deleted(self, event):
        self.process(event)

    def on_moved(self, event):
        self.process(event)

def show_notification(title, message):
    try:
        icon_path = os.path.abspath("icon.png")
        script = f'display notification "{message}" with title "{title}" sound name "default"'
        subprocess.run(['osascript', '-e', script])
    except Exception as e:
        log_error(f"Error during notification: {e}")

def update_progress(value, max_value=100):
    gui_queue.put(lambda: progress_bar.config(value=value))
    gui_queue.put(lambda: progress_label.config(text=f"Progress: {value:.2f}%"))

def update_status(message):
    gui_queue.put(lambda: status_label.config(text=message))

def update_speed(speed):
    gui_queue.put(lambda: speed_label.config(text=f"Speed: {speed:.2f} MB/s"))

def update_data_transferred():
    gui_queue.put(lambda: data_transferred_label.config(text=f"Upload: {uploaded_data:.2f} MB | Download: {downloaded_data:.2f} MB"))

def update_file_hash(hash_value):
    gui_queue.put(lambda: hash_label.config(text=f"Hash: {hash_value}"))

def reset_session_timer():
    global session_start_time
    session_start_time = time.time()

def move_file_on_minio(old_file_name, new_file_name):
    try:
        s3 = boto3.client('s3',
                          endpoint_url=MINIO_ENDPOINT,
                          aws_access_key_id=MINIO_ACCESS_KEY,
                          aws_secret_access_key=MINIO_SECRET_KEY)
        s3.copy_object(Bucket=MINIO_BUCKET, CopySource={'Bucket': MINIO_BUCKET, 'Key': old_file_name}, Key=new_file_name)
        s3.delete_object(Bucket=MINIO_BUCKET, Key=old_file_name)
        for hash_key, file_name in file_hashes.items():
            if file_name == old_file_name:
                file_hashes[hash_key] = new_file_name
                break
        log_info(f"File {old_file_name} renamed on MinIO to {new_file_name}.")
        gui_queue.put(lambda: show_notification("MinIO File Sync", f"File {old_file_name} renamed on MinIO to {new_file_name}."))
    except ClientError as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except Exception as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))

def upload_file_to_minio(file_path):
    global uploaded_data
    try:
        if os.path.basename(file_path).startswith('.') or os.path.basename(file_path) == ".DS_Store":
            log_info(f"File {file_path} ignored.")
            uploading_files.discard(file_path)
            return

        s3 = boto3.client('s3', 
                          endpoint_url=MINIO_ENDPOINT,
                          aws_access_key_id=MINIO_ACCESS_KEY,
                          aws_secret_access_key=MINIO_SECRET_KEY)
        file_size = os.path.getsize(file_path)
        chunk_size = 5 * 1024 * 1024  # 5 MB
        relative_path = os.path.relpath(file_path, config.get("directory_to_watch"))
        file_name = relative_path.replace(os.sep, "/")
        
        local_hash = calculate_file_hash(file_path)
        update_file_hash(local_hash)
        
        # Check if the hash already exists
        if local_hash in file_hashes and file_hashes[local_hash] != file_name:
            log_info(f"File {file_path} renamed from {file_hashes[local_hash]} to {file_name}.")
            move_file_on_minio(file_hashes[local_hash], file_name)
            uploading_files.discard(file_path)
            return
        
        gui_queue.put(lambda: update_status(f"Uploading {file_name}"))
        
        if file_size <= chunk_size:
            # Normal upload for small files
            start_time = time.time()
            s3.upload_file(file_path, MINIO_BUCKET, file_name)
            end_time = time.time()
            speed = file_size / (1024 * 1024) / (end_time - start_time)
            uploaded_data += file_size / (1024 * 1024)
            
            # Verify file integrity
            s3.download_file(MINIO_BUCKET, file_name, f"/tmp/{file_name}")
            remote_hash = calculate_file_hash(f"/tmp/{file_name}")
            if local_hash != remote_hash:
                raise ValueError("File hash mismatch after upload")
            
            file_hashes[local_hash] = file_name
            message = messages["upload_completed"].format(file_path=file_path)
            log_info(message)
            gui_queue.put(lambda: show_notification("MinIO File Sync", message))
            gui_queue.put(lambda: update_progress(100))
            gui_queue.put(lambda: update_status("Upload completed"))
            gui_queue.put(lambda: update_speed(speed))
            gui_queue.put(lambda: update_data_transferred())
        else:
            # Multipart upload for large files
            num_chunks = file_size // chunk_size + 1
            multipart_upload = s3.create_multipart_upload(Bucket=MINIO_BUCKET, Key=file_name)
            parts = []
            with open(file_path, 'rb') as f:
                for i in range(num_chunks):
                    start_time = time.time()
                    chunk = f.read(chunk_size)
                    part_num = i + 1
                    try:
                        part = s3.upload_part(Body=chunk, Bucket=MINIO_BUCKET, Key=file_name,
                                              UploadId=multipart_upload['UploadId'], PartNumber=part_num)
                        parts.append({"PartNumber": part_num, "ETag": part['ETag']})
                        end_time = time.time()
                        speed = len(chunk) / (1024 * 1024) / (end_time - start_time)
                        progress = part_num / num_chunks * 100
                        uploaded_data += len(chunk) / (1024 * 1024)
                        gui_queue.put(lambda: update_progress(progress))
                        gui_queue.put(lambda: update_speed(speed))
                        gui_queue.put(lambda: update_status(f"Uploading {file_name} - {progress:.2f}%"))
                        gui_queue.put(lambda: update_data_transferred())
                    except ClientError as e:
                        log_error(f"Error uploading chunk: {e}")
                        s3.abort_multipart_upload(Bucket=MINIO_BUCKET, Key=file_name, UploadId=multipart_upload['UploadId'])
                        raise e
            try:
                s3.complete_multipart_upload(Bucket=MINIO_BUCKET, Key=file_name, 
                                             UploadId=multipart_upload['UploadId'], MultipartUpload={"Parts": parts})
                # Verify file integrity
                s3.download_file(MINIO_BUCKET, file_name, f"/tmp/{file_name}")
                remote_hash = calculate_file_hash(f"/tmp/{file_name}")
                if local_hash != remote_hash:
                    raise ValueError("File hash mismatch after upload")
                
                file_hashes[local_hash] = file_name
                message = messages["upload_completed"].format(file_path=file_path)
                log_info(message)
                gui_queue.put(lambda: show_notification("MinIO File Sync", message))
                gui_queue.put(lambda: update_progress(100))
                gui_queue.put(lambda: update_status("Upload completed"))
                gui_queue.put(lambda: update_speed(0))
            except ClientError as e:
                log_error(f"Error completing multipart upload: {e}")
                raise e
    except FileNotFoundError:
        message = messages["file_not_found"]
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except NoCredentialsError:
        message = messages["invalid_credentials"]
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except ClientError as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except Exception as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    finally:
        uploading_files.discard(file_path)

def download_file_from_minio(file_name, download_path):
    global downloaded_data
    try:
        s3 = boto3.client('s3',
                          endpoint_url=MINIO_ENDPOINT,
                          aws_access_key_id=MINIO_ACCESS_KEY,
                          aws_secret_access_key=MINIO_SECRET_KEY)
        meta = s3.head_object(Bucket=MINIO_BUCKET, Key=file_name)
        file_size = meta['ContentLength']
        chunk_size = 5 * 1024 * 1024  # 5 MB

        # Create folder if it doesn't exist
        os.makedirs(os.path.dirname(download_path), exist_ok=True)

        # Check if the file already exists locally and has the same size
        if os.path.exists(download_path) and os.path.getsize(download_path) == file_size:
            log_info(f"File {download_path} already exists and is up to date.")
            return
        
        gui_queue.put(lambda: update_status(f"Downloading {file_name}"))
        
        if file_size <= chunk_size:
            # Normal download for small files
            start_time = time.time()
            s3.download_file(MINIO_BUCKET, file_name, download_path)
            end_time = time.time()
            speed = file_size / (1024 * 1024) / (end_time - start_time)
            downloaded_data += file_size / (1024 * 1024)
            
            # Verify file integrity
            local_hash = calculate_file_hash(download_path)
            remote_hash = calculate_file_hash(f"/tmp/{file_name}")
            if local_hash != remote_hash:
                raise ValueError("File hash mismatch after download")
            
            message = messages["download_completed"].format(file_name=file_name, download_path=download_path)
            log_info(message)
            gui_queue.put(lambda: show_notification("MinIO File Sync", message))
            gui_queue.put(lambda: update_progress(100))
            gui_queue.put(lambda: update_status("Download completed"))
            gui_queue.put(lambda: update_speed(speed))
            gui_queue.put(lambda: update_data_transferred())
        else:
            # Multipart download for large files
            num_chunks = file_size // chunk_size + 1
            with open(download_path, 'wb') as f:
                for i in range(num_chunks):
                    start_byte = i * chunk_size
                    end_byte = min(start_byte + chunk_size - 1, file_size - 1)
                    start_time = time.time()
                    response = s3.get_object(Bucket=MINIO_BUCKET, Key=file_name, Range=f'bytes={start_byte}-{end_byte}')
                    chunk = response['Body'].read()
                    f.write(chunk)
                    end_time = time.time()
                    speed = len(chunk) / (1024 * 1024) / (end_time - start_time)
                    progress = (i + 1) / num_chunks * 100
                    downloaded_data += len(chunk) / (1024 * 1024)
                    gui_queue.put(lambda: update_progress(progress))
                    gui_queue.put(lambda: update_speed(speed))
                    gui_queue.put(lambda: update_status(f"Downloading {file_name} - {progress:.2f}%"))
                    gui_queue.put(lambda: update_data_transferred())
            message = messages["download_completed"].format(file_name=file_name, download_path=download_path)
            log_info(message)
            gui_queue.put(lambda: show_notification("MinIO File Sync", message))
            gui_queue.put(lambda: update_progress(100))
            gui_queue.put(lambda: update_status("Download completed"))
            gui_queue.put(lambda: update_speed(0))
    except FileNotFoundError:
        message = messages["file_not_found"]
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except NoCredentialsError:
        message = messages["invalid_credentials"]
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except ClientError as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except Exception as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))

def delete_file_from_minio(file_name):
    try:
        s3 = boto3.client('s3',
                          endpoint_url=MINIO_ENDPOINT,
                          aws_access_key_id=MINIO_ACCESS_KEY,
                          aws_secret_access_key=MINIO_SECRET_KEY)
        s3.delete_object(Bucket=MINIO_BUCKET, Key=file_name)
        message = messages["deletion_completed"].format(file_name=file_name)
        log_info(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
    except ClientError as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except Exception as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))

def delete_local_file(file_path):
    try:
        os.remove(file_path)
        message = messages["deletion_local_completed"].format(file_path=file_path)
        log_info(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
    except Exception as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: show_notification("MinIO File Sync", message))
        gui_queue.put(lambda: update_status(f"Error: {message}"))

def download_all_files(directory):
    try:
        s3 = boto3.client('s3',
                          endpoint_url=MINIO_ENDPOINT,
                          aws_access_key_id=MINIO_ACCESS_KEY,
                          aws_secret_access_key=MINIO_SECRET_KEY)
        response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
        if 'Contents' in response:
            minio_files = {obj['Key'] for obj in response['Contents']}
            local_files = {os.path.relpath(os.path.join(root, file), directory).replace(os.sep, "/")
                           for root, _, files in os.walk(directory) for file in files}
            
            # Upload local files to MinIO if they don't exist on MinIO
            for file_name in local_files - minio_files:
                upload_file_to_minio(os.path.join(directory, file_name.replace("/", os.sep)))
            
            # Download missing files from MinIO
            for file_name in minio_files - local_files:
                download_path = os.path.join(directory, file_name.replace("/", os.sep))
                download_file_from_minio(file_name, download_path)
            
            # Delete files that are only on MinIO
            for file_name in minio_files - local_files:
                delete_file_from_minio(file_name)
            
            # Delete files that are only local
            for file_name in local_files - minio_files:
                delete_local_file(os.path.join(directory, file_name.replace("/", os.sep)))
    except NoCredentialsError:
        message = messages["invalid_credentials"]
        log_error(message)
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except ClientError as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: update_status(f"Error: {message}"))
    except Exception as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
        gui_queue.put(lambda: update_status(f"Error: {message}"))

# Optimized synchronization with lock
sync_lock = threading.Lock()

def check_server_connection():
    while True:
        try:
            s3 = boto3.client('s3',
                              endpoint_url=MINIO_ENDPOINT,
                              aws_access_key_id=MINIO_ACCESS_KEY,
                              aws_secret_access_key=MINIO_SECRET_KEY)
            s3.list_buckets()
            if not is_connected.is_set():
                is_connected.set()
                reset_session_timer()
                gui_queue.put(lambda: update_status(messages["server_connected"]))
        except:
            if is_connected.is_set():
                is_connected.clear()
                gui_queue.put(lambda: update_status(messages["server_disconnected"]))
        time.sleep(10)

def sync_with_minio(directory):
    while True:
        with sync_lock:
            if not is_paused.is_set() and is_connected.is_set():
                try:
                    s3 = boto3.client('s3',
                                      endpoint_url=MINIO_ENDPOINT,
                                      aws_access_key_id=MINIO_ACCESS_KEY,
                                      aws_secret_access_key=MINIO_SECRET_KEY)
                    response = s3.list_objects_v2(Bucket=MINIO_BUCKET)
                    if 'Contents' in response:
                        minio_files = {obj['Key'] for obj in response['Contents']}
                        local_files = {os.path.relpath(os.path.join(root, file), directory).replace(os.sep, "/")
                                       for root, _, files in os.walk(directory) for file in files}
                        
                        # Upload local files to MinIO if they don't exist on MinIO
                        for file_name in local_files - minio_files:
                            if not file_name.startswith('.') and not file_name == ".DS_Store":
                                upload_file_to_minio(os.path.join(directory, file_name.replace("/", os.sep)))
                        
                        # Download missing files from MinIO
                        for file_name in minio_files - local_files:
                            download_path = os.path.join(directory, file_name.replace("/", os.sep))
                            download_file_from_minio(file_name, download_path)
                        
                        # Delete files that are only on MinIO
                        for file_name in minio_files - local_files:
                            delete_file_from_minio(file_name)
                        
                        # Delete files that are only local
                        for file_name in local_files - minio_files:
                            delete_local_file(os.path.join(directory, file_name.replace("/", os.sep)))
                except NoCredentialsError:
                    message = messages["invalid_credentials"]
                    log_error(message)
                    gui_queue.put(lambda: update_status(f"Error: {message}"))
                except ClientError as e:
                    message = messages["generic_error"].format(error=e)
                    log_error(message)
                    gui_queue.put(lambda: update_status(f"Error: {message}"))
                except Exception as e:
                    message = messages["generic_error"].format(error=e)
                    log_error(message)
                    gui_queue.put(lambda: update_status(f"Error: {message}"))
        time.sleep(CHECK_INTERVAL)

def toggle_sync():
    if is_paused.is_set():
        is_paused.clear()
        gui_queue.put(lambda: sync_button.config(text=messages["pause_sync"]))
    else:
        is_paused.set()
        gui_queue.put(lambda: sync_button.config(text=messages["resume_sync"]))

def save_directory_config(directory):
    try:
        config['directory_to_watch'] = directory
        with open(CONFIG_FILE, 'w') as config_file:
            json.dump(config, config_file)
    except Exception as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)

def load_directory_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as config_file:
                config = json.load(config_file)
                return config.get('directory_to_watch')
    except Exception as e:
        message = messages["generic_error"].format(error=e)
        log_error(message)
    return None

def select_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        save_directory_config(folder_path)
        threading.Thread(target=download_all_files, args=(folder_path,), daemon=True).start()
        start_watching(folder_path)
        start_syncing(folder_path)
        messagebox.showinfo("Success", messages["sync_started"].format(folder_path=folder_path))
    else:
        messagebox.showwarning("Warning", "No folder selected.")

def select_language():
    def save_language():
        selected_language = language_var.get()
        config['language'] = selected_language
        with open(CONFIG_FILE, 'w') as config_file:
            json.dump(config, config_file)
        messagebox.showinfo("Success", "Language saved. Restart the application to apply the changes.")
    
    lang_window = tk.Toplevel(root)
    lang_window.title(messages["select_language"])
    
    ttk.Label(lang_window, text=messages["select_language"]).pack(pady=10)
    language_var = tk.StringVar(value=config.get('language', 'en'))
    
    languages = {"English": "en", "Italian": "it"}
    for text, value in languages.items():
        ttk.Radiobutton(lang_window, text=text, variable=language_var, value=value).pack(pady=5)
    
    ttk.Button(lang_window, text=messages["save"], command=save_language).pack(pady=20)

def start_watching(directory):
    watcher = Watcher(directory)
    watcher_thread = threading.Thread(target=watcher.run)
    watcher_thread.daemon = True
    watcher_thread.start()

def start_syncing(directory):
    sync_thread = threading.Thread(target=sync_with_minio, args=(directory,))
    sync_thread.daemon = True
    sync_thread.start()

def start_server_check():
    server_check_thread = threading.Thread(target=check_server_connection)
    server_check_thread.daemon = True
    server_check_thread.start()

def on_quit(icon, item):
    icon.stop()
    gui_queue.put(lambda: root.quit())

def show_window(icon, item):
    icon.stop()
    gui_queue.put(lambda: root.deiconify())

def hide_window():
    root.withdraw()
    image = Image.open("icon.png")
    menu = (item('Show', show_window), item('Quit', on_quit))
    icon = pystray.Icon("name", image, "MinIO Sync", menu)
    threading.Thread(target=icon.run).start()

# Create the main window
root = tk.Tk()
root.title("MinIO File Sync")
root.geometry("500x450")
root.resizable(False, False)

# Load icon
try:
    icon_img = ImageTk.PhotoImage(Image.open("icon.png"))
    root.iconphoto(False, icon_img)
except Exception as e:
    log_error(f"Error loading icon: {e}")

# Add session duration counter
session_start_time = time.time()
session_label = ttk.Label(root, text="Session duration: 00:00:00")
session_label.pack(pady=5)

def update_session_duration():
    if is_connected.is_set():
        elapsed_time = time.time() - session_start_time
        elapsed_time_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
        session_label.config(text=messages["session_duration"].format(duration=elapsed_time_str))
    else:
        session_label.config(text=messages["session_duration"].format(duration="00:00:00"))
    root.after(1000, update_session_duration)

# GUI structure with Frame
main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True)

# Button to select the folder to sync
select_folder_button = ttk.Button(main_frame, text=messages["select_folder"], command=select_folder)
select_folder_button.pack(pady=10)

# Button to select language
language_button = ttk.Button(main_frame, text=messages["select_language"], command=select_language)
language_button.pack(pady=10)

# Progress bar
progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

# Progress percentage label
progress_label = ttk.Label(main_frame, text="Progress: 0.00%")
progress_label.pack(pady=5)

# Status label
status_label = ttk.Label(main_frame, text="Status: Waiting for folder selection")
status_label.pack(pady=10)

# Transfer speed label
speed_label = ttk.Label(main_frame, text="Speed: 0.00 MB/s")
speed_label.pack(pady=5)

# File hash label
hash_label = ttk.Label(main_frame, text="Hash: ")
hash_label.pack(pady=5)

# Transferred data label
data_transferred_label = ttk.Label(main_frame, text="Upload: 0.00 MB | Download: 0.00 MB")
data_transferred_label.pack(pady=5)

# Pause/resume button
sync_button = ttk.Button(main_frame, text=messages["pause_sync"], command=toggle_sync)
sync_button.pack(pady=10)

# Load saved configuration
saved_directory = load_directory_config()
if saved_directory:
    threading.Thread(target=download_all_files, args=(saved_directory,), daemon=True).start()
    start_watching(saved_directory)
    start_syncing(saved_directory)
    messagebox.showinfo("Success", messages["sync_started"].format(folder_path=saved_directory))

# Hide the window and show the tray icon when the window is closed
root.protocol('WM_DELETE_WINDOW', hide_window)

def process_gui_queue():
    while not gui_queue.empty():
        task = gui_queue.get()
        task()

    root.after(100, process_gui_queue)

# Start the main GUI loop
root.after(100, process_gui_queue)
update_session_duration()
start_server_check()
root.mainloop()
