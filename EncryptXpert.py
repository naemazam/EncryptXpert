EX_Version = 1.0 # Don't Change it 

import os
from os import path
import json

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Log Errors #
ERRORS = {
	'[F-0]':"Files should not be more than 64GB.",
	'[F-1]':"You have selected files thar are more than 64GB.",
	'[F-2]':"Some files you selected do not exist.",
	'[F_UC-0]':"Please check back later or contact with Naem Azam. Probably there is an update on the way!",
	'[F_UC-1]':"Please check your internet connection.",
	'[F_UC-2]':"HTTP Error.",
	'[F_UC-3]':"Error Connecting.",
	'[F_UC-4]':"Timeout Error.",
	'[DB_KNS-0]':"Something is wrong with the DB file.",
	'[DB_KNS-1]':"DB file does not exist.",
	'[DB_DBFC-0]':"Something is wrong with the DB file.",
	'[DB_DKNC-0]':"Something is wrong with DB file.",
	'[AES_E-0]':"This key has been used already. Please enter a unique one.",
	'[AES_E-1]':"Please enter a key up to 32 characters.",
	'[AES_E-2]':"Please enter a key up to 32 characters.",
	'[AES_E-3]':"File does not exist.",
	'[AES_D-0]':"Please enter key and nonce to decrypt.",
	'[AES_D-1]':"Please check your key's hex format.",
	'[AES_D-2]':"Please check your nonce's hex format.",
	'[AES_D-3]':"Please check your key and nonce.",
	'[AES_D-4]':"Please enter a key up to 32 characters.",
	'[AES_D-5]':"Your key or nonce is incorrect.",
	'[AES_D-6]':"This file is not encrypted.",
	'[UI_DBB-0]':'Something is wrong with this DB file.',
	'[UI_DBB-1]':'This file contains characters that are not understandable.'
}

# Log Function #

def Logger(mtype, message):
	if mtype =='fileslistimport':
		Logger('info',"You have selected:")
		for i in message:
			UIWindow.Logger.appendPlainText(i)
	else:
		if mtype == 'warn':
			message = '[Warning] - ' + message
		elif mtype =='info':
			message = '[Info] - ' + message
		elif mtype =='imp':
			message = '[Important] - ' + message
		elif mtype =='error':
			message = '[Error] - ' + message + ' ' + ERRORS[message]

		UIWindow.Logger.appendPlainText(message)



class AES_SYSTEM():
	def EncSystem(self):
		self.cur_enc_system = UIWindow.Enc_system_label.text()
		if UIWindow.Enc_system_label.text() == 'AES-EAX':
			return AES.MODE_EAX
		else:
			self.cur_enc_system = 'AES-GCM'
			return AES.MODE_GCM

	def Encrypt(self):
		for self.address in UIWindow.files_list:
			if not path.exists(self.address):
				Logger('error','[AES_E-3]')
				continue

			UIWindow.SetShortcuts('cur_file',self.address)

			self.filesize = os.path.getsize(self.address)/pow(1024,3)

			if self.filesize >= 64: # If file is >= 64GB, you should split file to smaller parts cause of encryption security reasons
				Logger('error','[AES_E-2]')
				continue


			## ENCRYPTION KEY
			if UIWindow.enc_key_input.text(): # KEY
				if UIWindow.enc_key_label.text() == 'Key (B):': # Bytes format key
					## Check key's length
					if len(UIWindow.enc_key_input.text()) <= 31:
						self.key = pad(UIWindow.enc_key_input.text().encode() ,32) # pad key in total of 32 bytes (256bit)
					elif len(UIWindow.enc_key_input.text()) == 32:
						self.key = UIWindow.enc_key_input.text().encode()
					else:
						Logger('error','[AES_E-1]')
						continue

				else: # Hex format key
					try:
						self.key = UIWindow.enc_key_input.text()
						bytes.fromhex(self.key)
					except ValueError:
						Logger('error',"Please enter a key in Hex format.")
						continue

				if UIWindow.option_Check_for_dublicate_key_nonce_in_DB.isChecked():
					if self.DoubleKeyNonceChecker('key'):
						Logger('error','[AES_E-0]')
						continue

			else: # Generate key
				self.key = get_random_bytes(UIWindow.key_gen_bits.value()//8)
				if UIWindow.option_Check_for_dublicate_key_nonce_in_DB.isChecked():
					while self.DoubleKeyNonceChecker('key'):
						self.key = get_random_bytes(UIWindow.key_gen_bits.value()//8)
				Logger('info',f"Generated Key: {self.key.hex()}")
					
			## NONCE
			cipher = AES.new(self.key, self.EncSystem()) # AES Encryption System
			self.nonce = cipher.nonce # Generated Nonce

			if UIWindow.option_Check_for_dublicate_key_nonce_in_DB.isChecked(): # Check if nonce already exists
				while self.DoubleKeyNonceChecker('nonce'):
					cipher = AES.new(self.key, self.EncSystem()) # AES Encryption System
					self.nonce = cipher.nonce # Nonce Generate
			Logger('info',f"Generated Nonce: {self.nonce.hex()}")


			## Basic Actions
			UIWindow.enc_button.setEnabled(False)
			UIWindow.dec_button.setEnabled(False)
			UIWindow.dec_progressBar.setFormat('')
			UIWindow.enc_files_counter_progressBar.setFormat(f'{UIWindow.files_counter}/{UIWindow.enc_files_counter_progressBar.maximum()}') # files counter bar 0/$num_of_files
			file_blocks = os.path.getsize(self.address)//UIWindow.USABLE_RAM # file's blocks calculation
			counter = 0

			## ENCRYPTION PROCESS
			with open(self.address, 'rb') as file:
				with open(self.address + UIWindow.FILE_EXT, 'wb') as enc_file:
					fb = file.read(UIWindow.USABLE_RAM) # read first $UIWindow.USABLE_RAM bytes

					while len(fb) > 0: # While there is still data being read from the file

						if file_blocks != 0: # Print Encryption Progress
							UIWindow.enc_progressBar.setValue(counter*100//file_blocks)
							UIWindow.enc_progressBar.setFormat( str(counter*100//file_blocks) + '%' )

						enc_file.write(cipher.encrypt(fb))
						fb = file.read(UIWindow.USABLE_RAM) # Read the next block of the file
						counter += 1

			## Tag
			self.tag = cipher.digest() # Calculate tag
			UIWindow.enc_progressBar.setValue(100)
			UIWindow.enc_progressBar.setFormat( '100%' )
			Logger('info',f"File has been successfully encrypted: {self.address}")

			## Files Counter
			UIWindow.files_counter += 1
			UIWindow.enc_files_counter_progressBar.setValue(UIWindow.files_counter)
			UIWindow.enc_files_counter_progressBar.setFormat(f'{UIWindow.files_counter}/{UIWindow.enc_files_counter_progressBar.maximum()}')

			if UIWindow.option_Delete_original_file.isChecked(): # Delete original file
				self.DeleteOriginalFile()
			
			
			if UIWindow.option_Store_key_nonce_in_DB.isChecked(): # Save key/nonce/tag
				self.filehash = self.sha256Hash(self.address + UIWindow.FILE_EXT) # calculate encfile hash
				self.SaveKeyNonceTag() # save hash,key,nonce to database		



	def Decrypt(self):
		for self.address in UIWindow.files_list:
			UIWindow.SetShortcuts('cur_file',self.address)

			if self.ManyFilesSelected: # If file is already encrypted, check if it's key/nonce exist in DB
				self.filehash = self.sha256Hash(self.address)
				self.KeyNonceSearcher()

			if not self.address.endswith(UIWindow.FILE_EXT):
				Logger('error',"[AES_D-6]")
				continue
					
			## KEY & NONCE inputs
			if not (UIWindow.dec_key_input.text() and UIWindow.dec_nonce_input.text()): # If key/nonce have not been filled, then stop
				Logger('error','[AES_D-0]')
				continue

			if UIWindow.dec_key_label.text() == 'Key (H):': # Hex format key
				try:
					self.key = bytes.fromhex(UIWindow.dec_key_input.text())
				except ValueError:
					Logger('error','[AES_D-1]')
					continue

			else: # Bytes format key
				if len(UIWindow.dec_key_input.text()) <= 31:
					self.key = pad(UIWindow.dec_key_input.text().encode(),32) # pad key in total of 32 bytes (256bit)
				elif len(UIWindow.dec_key_input.text()) == 32:
					self.key = UIWindow.dec_key_input.text().encode()
				else:
					Logger('error','[AES_D-4]')
					continue

			try: # Check nonce's hex format
				self.nonce = bytes.fromhex(UIWindow.dec_nonce_input.text())
			except ValueError:
				Logger('error','[AES_D-2]')
				continue

			try:
				cipher = AES.new( self.key, self.EncSystem(), nonce=self.nonce ) # AES Encryption System
			except ValueError:
				Logger('error','[AES_D-3]')
				continue


			## Basic Actions
			UIWindow.enc_button.setEnabled(False)
			UIWindow.dec_button.setEnabled(False)
			UIWindow.enc_progressBar.setFormat('')
			UIWindow.dec_files_counter_progressBar.setFormat(f'{UIWindow.files_counter}/{UIWindow.dec_files_counter_progressBar.maximum()}') # files counter bar 0/$num_of_files


			file_blocks = os.path.getsize(self.address)//UIWindow.USABLE_RAM # file blocks calculation
			counter = 0

			## DECRYPT PROCESS
			with open(self.address, 'rb') as file:
				with open(self.address[:-len(UIWindow.FILE_EXT)],'wb') as dec_file:
					fb = file.read(UIWindow.USABLE_RAM) # read first $UIWindow.USABLE_RAM bytes
					while len(fb) > 0: # While there is still data being read from the file
						if file_blocks != 0:
							UIWindow.dec_progressBar.setValue(counter*100//file_blocks)
							UIWindow.dec_progressBar.setFormat(str(counter*100//file_blocks) + '%' )
						dec_file.write(cipher.decrypt(fb))
						fb = file.read(UIWindow.USABLE_RAM) # Read the next block from the file
						counter += 1

			## DECRYPTION VERIFICATION
			try: # if tag exists
				if self.tag:
					try:
						cipher.verify(self.tag)
						Logger('info',f"File has been successfully decrypted and verified:\n{self.address}")
						dec_verified = 1
					except ValueError:
						Logger('error',"[AES_D-5]")
						UIWindow.dec_button.setEnabled(True)
						UIWindow.dec_button.setEnabled(True)
						UIWindow.dec_progressBar.setFormat('Ready To Decrypt')
						UIWindow.enc_progressBar.setFormat('Ready To Encrypt')
						try:
							os.remove(self.address[:-len(UIWindow.FILE_EXT)])
						except PermissionError:
							Logger('warn',"EX does not have permission to delete trash file.")
						continue
			except AttributeError:
				Logger('info',f"File has been successfully decrypted but not verified.")
				dec_verified = 0

			## Decryption process Counter
			UIWindow.dec_progressBar.setValue(100)
			UIWindow.dec_progressBar.setFormat( '100%' )
			
			## Files Counter
			UIWindow.files_counter += 1
			UIWindow.dec_files_counter_progressBar.setValue(UIWindow.files_counter)
			UIWindow.dec_files_counter_progressBar.setFormat(f'{UIWindow.files_counter}/{UIWindow.dec_files_counter_progressBar.maximum()}')

			if not dec_verified: # If Decryption not verified
				if not UIWindow.option_not_decrypted_verified_keep_original_file.isChecked(): # Delete original file
					if UIWindow.option_Delete_original_file.isChecked():
						self.DeleteOriginalFile()
				if not UIWindow.option_not_verified_keep_key_nonce_DB.isChecked(): # delete hash,key,nonce,tag from database
					if UIWindow.option_Delete_key_nonce_after_decryption.isChecked():
						self.DeleteKeyNonce()

			else: # If Decryption verified
				if UIWindow.option_Delete_original_file.isChecked(): # Delete original file
					self.DeleteOriginalFile()
				if UIWindow.option_Delete_key_nonce_after_decryption.isChecked() and self.KeyNonceSearcher(): # delete hash,key,nonce,tag from database
					self.DeleteKeyNonce()
					UIWindow.dec_key_input.setText('')
					UIWindow.dec_nonce_input.setText('')
				


	def DeleteOriginalFile(self):
		try:
			os.remove(self.address)
			Logger('info',"Original file has been deleted.")
		except PermissionError:
			Logger('warn',"we does not have permission to delete original file.")


	def sha256Hash(self, address):
		file_hash = hashlib.sha256()

		with open(address, 'rb') as f: # Open the file to read it's bytes
			fb = f.read(UIWindow.USABLE_RAM) # Read from the file. Take in the amount declared above

			while len(fb) > 0: # While there is still data being read from the file
				file_hash.update(fb) # Update the hash
				fb = f.read(UIWindow.USABLE_RAM) # Read the next block from the file

			return file_hash.hexdigest()



class DB():
	def SaveKeyNonceTag(self): # { hash : [ key, nonce, tag, enc_system, file_name ] }
		if self.DBFileChecker():
			with open(UIWindow.DATABASE_FILE, 'r+') as DB_file:
				try:
					data = json.load(DB_file)
				except json.decoder.JSONDecodeError:
					data = {}
				finally:
					data[self.filehash] =  [self.key.hex() , self.nonce.hex(), self.tag.hex(), UIWindow.Enc_system_label.text(), self.address]
					DB_file.seek(0)
					json.dump(data, DB_file)
					DB_file.truncate()
					Logger('info',"Key and Nonce have been saved in DB.")


	def DeleteKeyNonce(self):
		if self.DBFileChecker():
			try:
				with open(UIWindow.DATABASE_FILE, 'r+') as DB_file:
					data = json.load(DB_file)
					del data[self.filehash]
					DB_file.seek(0)
					json.dump(data, DB_file)
					DB_file.truncate()
			except FileNotFoundError:
				Logger('warn','DB file could not be found to delete key and nonce.')


	def KeyNonceSearcher(self): # { hash : [ key, nonce, tag, enc_system ] }
		if self.DBFileChecker():
			try:
				with open(UIWindow.DATABASE_FILE, 'r') as DB_file:
					data = json.load(DB_file)

					if self.filehash in data:
						Logger('info',"File's key/nonce have been found in the database.")
						UIWindow.dec_key_label.setText('Key (H):')
						UIWindow.dec_key_input.setText(data[self.filehash][0])
						UIWindow.dec_nonce_input.setText(data[self.filehash][1])
						self.tag = bytes.fromhex(data[self.filehash][2])
						UIWindow.Enc_system_label.setText(data[self.filehash][3])
						return True
					else:
						return False

			except json.decoder.JSONDecodeError:
				Logger('error','[DB_KNS-0]')
				UIWindow.DATABASE_FILE = UIWindow.DATABASE_FILE + '_tempfile.txt'
				with open(UIWindow.DATABASE_FILE, 'w') as DB_file:
					data = {}
					json.dump(data, DB_file)
				Logger('info',f'New DB file has been created: {os.getcwd()}\\{UIWindow.DATABASE_FILE}')
				UIWindow.SetShortcuts('DB')
		else:
			return False


	def DoubleKeyNonceChecker(self,obj):
		if self.DBFileChecker():
			try:
				with open(UIWindow.DATABASE_FILE, 'r') as DB_file:
					data = DB_file.read()
					if obj == 'key':
						return (self.key.hex() in data)
					else:
						return (self.nonce.hex() in data)

			except json.decoder.JSONDecodeError:
				Logger('error','[DB_DKNC-0]')
				Logger('info','Encryption continues without key/nonce check.')
				return True
		else:
			return True
	

	def DBFileChecker(self):
		if UIWindow.DATABASE_FILE != None:
			if path.exists(UIWindow.DATABASE_FILE):
				try:
					DB_file = open(UIWindow.DATABASE_FILE, 'r')
					DB_file.close()
				except Exception as e:
					print(e)
					UIWindow.DATABASE_FILE = 'EX_DB_tempfile.txt'
					Logger('error','[DB_DBFC-0]')
					with open(UIWindow.DATABASE_FILE, 'w') as DB_file:
						data = {}
						json.dump(data, DB_file)
					Logger('info',f'Created a temp DB file: {UIWindow.DATABASE_FILE}')
					UIWindow.SetShortcuts('DB')
					UIWindow.SaveOptions()
				return True
			else:
				UIWindow.SetShortcuts('DB-clear')
				Logger('error','[DB_KNS-1]')
				return False
		else:
			UIWindow.SetShortcuts('DB-clear')
			return False


	def NewDBFile(self):
		new_DB = QFileDialog.getSaveFileName(UIWindow, 'New Database')[0]
		if new_DB:
			with open(new_DB,'w') as New_DB_file:
				New_DB_file.write('{}')
			UIWindow.DATABASE_FILE = new_DB
			UIWindow.SetShortcuts('DB')
			UIWindow.SaveOptions()




class File(AES_SYSTEM,DB):
	def __init__(self, address_list):
		address_list = self.AddressFixer(address_list)

		if all([path.exists(x) for x in address_list]): # Check if all files exist

			if len(address_list) == 1: # If only one file has been selected
				self.ManyFilesSelected = False
				self.address = address_list[0]

				self.filesize = os.path.getsize(self.address)/pow(1024,3) # convert filesize from bytes to gigabytes

				if self.filesize < 64: # If file is >= 64GB, you should split file to smaller parts cause of encryption security reasons
					# Enable key/nonce inputs
					UIWindow.enc_key_input.setEnabled(True)
					UIWindow.dec_key_input.setEnabled(True)
					UIWindow.dec_nonce_input.setEnabled(True)

					# Enable enc/dec buttons
					UIWindow.enc_button.setEnabled(True)
					UIWindow.dec_button.setEnabled(True)
					UIWindow.enc_button.clicked.connect(lambda: self.Encrypt())
					UIWindow.dec_button.clicked.connect(lambda: self.Decrypt())

					Logger('fileslistimport', address_list)
					if self.address.endswith(UIWindow.FILE_EXT): # If file is already encrypted, check if it's key/nonce exist in DB
						self.filehash = self.sha256Hash(self.address)
						self.KeyNonceSearcher()

				else: # If file is bigger than 64GB
					Logger('error','[F-0]')

			else: # If many files are chosen
				self.ManyFilesSelected = True
				self.addresses = address_list
				Logger('fileslistimport', address_list) # print selected files
				
				if all([ os.path.getsize(x)/pow(1024,3) < 64 for x in self.addresses]): # Check if all files are <64GB
					if all([ UIWindow.FILE_EXT in x for x in self.addresses]): # Check if all files are encrypted ones
						Logger('info',"All selected files are already encrypted.")
					elif any([ UIWindow.FILE_EXT in x for x in self.addresses]):
						Logger('info',"Some selected files are already encrypted and some are not.")
					else:
						Logger('info',"All selected files are not encrypted.")

					## Disable enc/dec key/nonce inputs
					UIWindow.enc_key_input.setText('')
					UIWindow.enc_key_input.setEnabled(False)
					UIWindow.dec_key_input.setText('')
					UIWindow.dec_nonce_input.setText('')
					UIWindow.dec_key_input.setEnabled(False)
					UIWindow.dec_nonce_input.setEnabled(False)

					## Enable enc/dec buttons
					UIWindow.enc_button.setEnabled(True)
					UIWindow.dec_button.setEnabled(True)
					UIWindow.enc_button.clicked.connect(lambda: self.Encrypt())
					UIWindow.dec_button.clicked.connect(lambda: self.Decrypt())

				else:
					Logger('error','[F-1]')
		else:
			Logger('error','[F-2]')


	def AddressFixer(self, address_list):
		for i in range(len(address_list)):
			address_list[i] = os.path.abspath(address_list[i])
		return address_list


'''
Naem azam (Github: www.github.com/naemazam ), China 
'''

#### UI Area

from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QTextEdit, QFileDialog, QSlider, QHBoxLayout, QLabel
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import sys
from PyQt5 import uic


def clickable(widget): # https://wiki.python.org/moin/PyQt/Making%20non-clickable%20widgets%20clickable

	class Filter(QObject):
		clicked = pyqtSignal()

		def eventFilter(self, obj, event):
			if obj == widget:
				if event.type() == QEvent.MouseButtonRelease:
					if obj.rect().contains(event.pos()):
						self.clicked.emit()
						# The developer can opt for .emit(obj) to get the object within the slot.
						return True
			return False
	
	filter = Filter(widget)
	widget.installEventFilter(filter)
	return filter.clicked



class RamToUse(QWidget):
	def RamToUseOpenWindow(self):
		if UIWindow.RamToUseUIWindow is None: # If window is not opened
			UIWindow.RamToUseUIWindow = RamToUse()
		UIWindow.RamToUseUIWindow.show()

	def __init__(self):
		super().__init__()
		self.initUI()

	def initUI(self): # https://zetcode.com/pyqt/qslider/

		import psutil
		hbox = QHBoxLayout()

		## Side Bar
		self.slide_bar = QSlider(Qt.Horizontal, self)
		self.free_mb = int( psutil.virtual_memory().available//(1024**2) ) # Convert Bytes to MB
		self.slide_bar.setRange( 1, (self.free_mb - self.free_mb//10) ) # Let free at least 10% of the free RAM MB Minimum 65MB of RAM Need
		self.slide_bar.setValue(UIWindow.USABLE_RAM//(1024))
		self.slide_bar.setFocusPolicy(Qt.NoFocus)
		self.slide_bar.setPageStep(100)
		self.slide_bar.valueChanged.connect(self.updateLabel)

		## Side Bar Label
		self.slide_bar_value_label = QLabel(f'{UIWindow.USABLE_RAM//(1024)} MB | 0 GB\nRECOMMENDED', self)
		self.slide_bar_value_label.setStyleSheet("color: green;")
		self.slide_bar_value_label.setAlignment(Qt.AlignCenter | Qt.AlignVCenter)
		self.slide_bar_value_label.setMinimumWidth(80)

		## Window characteristics
		hbox.addWidget(self.slide_bar)
		hbox.addSpacing(15)
		hbox.addWidget(self.slide_bar_value_label)
		self.setLayout(hbox)
		self.setGeometry(300, 300, 350, 250)
		self.setWindowTitle('Usable RAM')
		self.show()


	def updateLabel(self, value):
		if value < 500: # If use up to 500 MB, show green
			self.slide_bar_value_label.setStyleSheet("color: green;")
			self.slide_bar_value_label.setText(f'{value} MB | {value//1024} GB\nRECOMMENDED')
		elif value < self.slide_bar.maximum()*0.75: # If use up to 75% of free space, show orange
			self.slide_bar_value_label.setStyleSheet("color: orange;")
			self.slide_bar_value_label.setText(f'{value} MB | {value//1024} GB')
		else: # If use more than 75% of free space, show red
			self.slide_bar_value_label.setStyleSheet("color: red;")
			self.slide_bar_value_label.setText(f'{value} MB | {value//1024} GB\nWARNING!')

		UIWindow.USABLE_RAM = value*1024 # convert mb to bytes



class UI(QMainWindow):

	def __init__(self):
		super(UI,self).__init__()
		uic.loadUi("EX_GUI.ui",self) # Load Main GUI
		self.setWindowTitle(f'EncryptXpert V{str(EX_Version)}') # Window Title and Version Number It Will Provide By master Dev.
		self.setWindowIcon(QIcon('images/Small_Logo.png')) # Window icon

		### Default variables ###
		self.DATABASE_FILE = None # Default key/nonce database
		self.FILE_EXT = '.encex'
		self.FEEDBACKURL = 'https://forms.gle/XipLRowrE7eTzht37' #Google From will collect Feedback from Customer.

		### Browse Button ###
		self.load_file_folder_button.clicked.connect(self.BrowseFiles) # Load File(s) Button

		### Progress Bars ###
		self.enc_progressBar.setAlignment(Qt.AlignCenter)
		self.dec_progressBar.setAlignment(Qt.AlignCenter)
		self.enc_files_counter_progressBar.setAlignment(Qt.AlignCenter)
		self.dec_files_counter_progressBar.setAlignment(Qt.AlignCenter)
		
		### Key labels ###
		clickable(self.enc_key_label).connect(lambda label_name="enc_key_label": self.LabelSwitcher(label_name) )
		clickable(self.dec_key_label).connect(lambda label_name="dec_key_label": self.LabelSwitcher(label_name) )

		### Encryption System label ###
		clickable(self.Enc_system_label).connect(lambda label_name="enc_system_label": self.LabelSwitcher(label_name) )

		### Options ###
		self.option_Check_for_Updates.triggered.connect(self.UpdateChecker) # Update Check
		self.RamToUseUIWindow = None ; self.option_Blocks_Size.triggered.connect(RamToUse.RamToUseOpenWindow) # Usable RAM
		self.option_Import_DB_file.triggered.connect(self.DBBrowser) # Import DB
		self.option_Save_Settings.triggered.connect(self.SaveOptions) # Save Options
		self.option_New_DB.triggered.connect(DB.NewDBFile) # New DB
		self.option_Feedback.triggered.connect(self.FeedBackRedirect) # Feedback

		### Shortcuts ###
		self.SetShortcuts('DB-clear')



		self.show()

	def UpdateChecker(self):
		import requests
		Logger('info',"Checking for new version...")

		try:
			try:
				url_response = requests.get("https://raw.githubusercontent.com/naemazam/EncryptXpert/main/EncryptXpert.py").text.split('\n')
				latest_version = float( url_response[0].split(' ')[2] ) # Check Update from Master Github Repo. No GUI Update.

				if latest_version > EX_Version:
					Logger('info',"There is a newer version! Please update EncryptXpert.")
					
				else:
					Logger('info',"You are up to date.")

			except ValueError:
				Logger('error',"[F_UC-0]")

		except requests.exceptions.RequestException:
				Logger('error',"[F_UC-1]")
		except requests.exceptions.HTTPError:
			Logger('error',"[F_UC-2]")
		except requests.exceptions.ConnectionError:
			Logger('error',"[F_UC-3]")
		except requests.exceptions.Timeout:
			Logger('error',"[F_UC-4]")   


	def BrowseFiles(self):
		self.files_list = QFileDialog.getOpenFileNames(self,'Single File','.','All Files (*.*)')[0]

		if self.option_Store_key_nonce_in_DB.isChecked(): # Check if DB file is working right (If user wants to store key/nonce). 
			DB.DBFileChecker(self) # No need Extra database Config, Auto set. 

		if len(self.files_list) > 0:

			try: # Clear enc/dec buttons (Pyqt5 issues)
				UIWindow.enc_button.clicked.disconnect()
				UIWindow.dec_button.clicked.disconnect()
			except TypeError:
				pass

			p1 = File(self.files_list) # Create file(s) object

			self.files_counter = 0
			UIWindow.enc_files_counter_progressBar.setMaximum(len(self.files_list))
			UIWindow.dec_files_counter_progressBar.setMaximum(len(self.files_list))
			self.enc_files_counter_progressBar.setValue(self.files_counter)
			self.enc_files_counter_progressBar.setFormat('')
			self.dec_files_counter_progressBar.setValue(self.files_counter)
			self.dec_files_counter_progressBar.setFormat('')

			## enc/dec ProgressBars ##
			self.enc_progressBar.setFormat('Ready To Encrypt')
			UIWindow.enc_progressBar.setValue(0)
			self.dec_progressBar.setFormat('Ready To Decrypt')
			UIWindow.dec_progressBar.setValue(0)



	def LabelSwitcher(self, label_name):
		if label_name == 'enc_key_label':
			if self.enc_key_label.text() == 'Key (B):':
				self.enc_key_label.setText('Key (H):')
				self.enc_key_input.setPlaceholderText('Type your key in Hex format (example: 736563726574313233)')
			else:
				self.enc_key_label.setText('Key (B):')
				self.enc_key_input.setPlaceholderText('Type your key in Bytes format (example: Azam123)')

		elif label_name == 'dec_key_label':
			if self.dec_key_label.text() == 'Key (B):':
				self.dec_key_label.setText('Key (H):')
				self.dec_key_input.setPlaceholderText('Type your key in Hex format (example: 736563726574313233)')
			else:
				self.dec_key_label.setText('Key (B):')
				self.dec_key_input.setPlaceholderText('Type your key in Bytes format (example: Azam123)')

		elif label_name == 'enc_system_label':
			if self.Enc_system_label.text() == 'AES-EAX':
				self.Enc_system_label.setText('AES-GCM')  # This are System label 
			else:
				self.Enc_system_label.setText('AES-EAX')


	def DBBrowser(self):
		DB_file_address = QFileDialog.getOpenFileName(self,'Single File','.','All Files (*.*)')[0]
		if DB_file_address and path.exists(DB_file_address):
			try:
				with open(DB_file_address, 'r') as DB_file:
					data = json.load(DB_file)
				self.DATABASE_FILE = DB_file_address
				Logger('info',f"{self.DATABASE_FILE} is now the new DB.")
				self.SetShortcuts('DB')
				self.SaveOptions()
			except (json.decoder.JSONDecodeError, UnicodeDecodeError) as e:
				Logger('error','[UI_DBB-0]')
			except UnicodeDecodeError:
				Logger('error','[UI_DBB-1]')


	def SetDefaultOptions(self):
		try: # If Options.txt exists and is okay
			OPT_file = open('Options.txt', 'r')
			options = json.load(OPT_file)
			if len(options) < 7: raise ValueError()

		except (json.decoder.JSONDecodeError, ValueError,FileNotFoundError): # If Options.txt has a problem, then remake it
			Logger('warn',"There was something wrong with options file.\nOptions have been set to default.")
			open('Options.txt', 'w').close() # Null file
			OPT_file = open('Options.txt', 'w') # Write default options
			options = {
				"DATABASE_FILE":None,
				"USABLE_RAM":65536,
				"option_not_verified_keep_key_nonce_DB":True,
				"option_Check_Update_on_program_startup":True,
				"option_Delete_original_file":True,
				"option_Store_key_nonce_in_DB":True,
				"option_Delete_key_nonce_after_decryption":True,
				"option_Check_for_dublicate_key_nonce_in_DB":True,
				"option_not_decrypted_verified_keep_original_file":True,
				"Enc_system_label":'AES-EAX'
				}

			try: # Check if Database file exists
				if not path.exists(options['DATABASE_FILE']):
					options["DATABASE_FILE"] = None
					self.DATABASE_FILE = None
			except TypeError as e:
				options["DATABASE_FILE"] = None
				self.DATABASE_FILE = None

			json.dump(options, OPT_file)


		try: # Check if Database file exists
			if not path.exists(options['DATABASE_FILE']):
				Logger('warn',f"The database file {options['DATABASE_FILE']} has not been found.")
				options["DATABASE_FILE"] = None
				self.DATABASE_FILE = None
		except TypeError as e:
			options["DATABASE_FILE"] = None
			self.DATABASE_FILE = None

		self.DATABASE_FILE = options['DATABASE_FILE']
		self.USABLE_RAM = options['USABLE_RAM']
		self.option_not_verified_keep_key_nonce_DB.setChecked(options['option_not_verified_keep_key_nonce_DB'])
		self.option_Check_Update_on_program_startup.setChecked(options['option_Check_Update_on_program_startup'])
		self.option_Delete_original_file.setChecked(options['option_Delete_original_file'])
		self.option_Store_key_nonce_in_DB.setChecked(options['option_Store_key_nonce_in_DB'])
		self.option_Delete_key_nonce_after_decryption.setChecked(options['option_Delete_key_nonce_after_decryption'])
		self.option_Check_for_dublicate_key_nonce_in_DB.setChecked(options['option_Check_for_dublicate_key_nonce_in_DB'])
		self.option_not_decrypted_verified_keep_original_file.setChecked(options['option_not_decrypted_verified_keep_original_file'])
		self.Enc_system_label.setText(options['Enc_system_label'])
		OPT_file.close()


	def SaveOptions(self):
		open('Options.txt', 'w').close() # Null file
		with open('Options.txt', 'w') as OPT_file:
			options = {
					"DATABASE_FILE":self.DATABASE_FILE,
					"USABLE_RAM":self.USABLE_RAM,
					"option_not_verified_keep_key_nonce_DB":self.option_not_verified_keep_key_nonce_DB.isChecked(),
					"option_Check_Update_on_program_startup":self.option_Check_Update_on_program_startup.isChecked(),
					"option_Delete_original_file":self.option_Delete_original_file.isChecked(),
					"option_Store_key_nonce_in_DB":self.option_Store_key_nonce_in_DB.isChecked(),
					"option_Delete_key_nonce_after_decryption":self.option_Delete_key_nonce_after_decryption.isChecked(),
					"option_Check_for_dublicate_key_nonce_in_DB":self.option_Check_for_dublicate_key_nonce_in_DB.isChecked(),
					"option_not_decrypted_verified_keep_original_file":self.option_not_decrypted_verified_keep_original_file.isChecked(),
					"Enc_system_label":self.Enc_system_label.text()
					}
			json.dump(options, OPT_file)


	def SetShortcuts(self,obj=None,f=None):
		if (obj == 'DB'):
			if self.DATABASE_FILE:
				self.DB_shortcut_value.setText(os.path.split(self.DATABASE_FILE)[1])
				## Enable DB options
				self.option_Store_key_nonce_in_DB.setEnabled(True)
				self.option_Delete_key_nonce_after_decryption.setEnabled(True)
				self.option_Check_for_dublicate_key_nonce_in_DB.setEnabled(True)
				self.option_not_verified_keep_key_nonce_DB.setEnabled(True)
				## Check DB options
				self.option_Store_key_nonce_in_DB.setChecked(True)
				self.option_Delete_key_nonce_after_decryption.setChecked(True)
				self.option_Check_for_dublicate_key_nonce_in_DB.setChecked(True)
				self.option_not_verified_keep_key_nonce_DB.setChecked(True)
				return
		elif (obj == 'cur_file'):
			self.Cur_file_shortcut_value.setText(os.path.split(f)[1])
			return
		elif (obj == 'DB-clear'):
			### Set default DB settings if no database file has been selected
			self.DATABASE_FILE = None
			self.DB_shortcut_value.setText('[None]')
			self.Cur_file_shortcut_value.setText('[None]')
			## Uncheck DB options
			self.option_Store_key_nonce_in_DB.setChecked(False)
			self.option_Delete_key_nonce_after_decryption.setChecked(False)
			self.option_Check_for_dublicate_key_nonce_in_DB.setChecked(False)
			self.option_not_verified_keep_key_nonce_DB.setChecked(False)
			## Disable DB options
			self.option_Store_key_nonce_in_DB.setEnabled(False)
			self.option_Delete_key_nonce_after_decryption.setEnabled(False)
			self.option_Check_for_dublicate_key_nonce_in_DB.setEnabled(False)
			self.option_not_verified_keep_key_nonce_DB.setEnabled(False)
			return


	def FeedBackRedirect(self):
		import webbrowser
		webbrowser.open_new(UIWindow.FEEDBACKURL)


if __name__ == "__main__":
	app = QApplication(sys.argv)

	UIWindow = UI() # Main Window
	UIWindow.SetDefaultOptions() # Set settings

	if UIWindow.option_Check_Update_on_program_startup.isChecked(): # AutoCheck for updates
		UIWindow.UpdateChecker()

	UIWindow.SetShortcuts('DB') # Set DB ShortCut

	app.exec_()
