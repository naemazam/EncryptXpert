<p align="center">
  <img src="https://github.com/naemazam/EncryptXpert/blob/main/banner.png" alt="EncryptXpert Banner">
</p>

# EncryptXpert

### An app for file encryption/decryption using AES-EAX or AES-GCM algorithms With GUI & CLI support and Build-in Key Database System For Windows Linux and Mac

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

EncryptXpert is a cutting-edge cybersecurity tool crafted in Python, delivering a comprehensive suite of features for safeguarding sensitive data. With both Graphical User Interface (GUI) and Command-Line Interface (CLI) support, EncryptXpert empowers users to encrypt and decrypt files effortlessly using advanced AES-EAX or AES-GCM algorithms.

This versatile solution ensures robust data protection across Windows and Linux platforms, offering a seamless user experience regardless of the operating system. The intuitive GUI interface simplifies encryption tasks, providing clear options for customizing encryption parameters to suit individual needs.

For users seeking automation or integration into existing workflows, EncryptXpert's CLI tools offer flexibility and efficiency. Whether encrypting single files or entire directories, EncryptXpert streamlines the encryption process while upholding stringent security standards.






## Demo

![Short Demo](https://github.com/naemazam/EncryptXpert/blob/main/Demo/encx.gif)

Watch Full Demo 


## Key Features:

- GUI and CLI tools for file encryption and decryption.
- Support for AES-EAX and AES-GCM encryption algorithms.
- Cross-platform compatibility with Windows and Linux environments.
- Intuitive interface for easy customization of encryption parameters.
- Seamless integration into automated workflows for streamlined encryption tasks.

EncryptXpert empowers users to take control of their data security, providing a reliable solution for protecting sensitive information in today's digital landscape. Whether securing personal files or safeguarding corporate assets, EncryptXpert offers a user-friendly and powerful encryption toolkit tailored to meet diverse cybersecurity needs.

# Pre-Requirements
- Python ( 3.9.0 or Higher )
- PyQT ( v5 or Higher )
- psutil
- pycryptodome

## Installation  

### Software Use ( Windows 10/11 )

Download The EXE File 

### Dev Use ( Linux/ Terminal )

Clone The Repo 
```bash
  git clone https://github.com/naemazam/EncryptXpert 
```

Navigate The Repo 

```bash
  cd EncryptXpert
```

Install all Required Packages

```bash
  pip install -r requirements.txt
```
Run The Model

```bash
  Python3 EncryptXpert.py
```
    
## Screenshots

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)


## Running Tests

To run tests, run the following command

```bash
  npm run test
```

## ⚠️ Warning: 
Please note that EncryptXpert may encounter occasional issues with the built-in key database system, leading to database failures. Additionally, file integrity may occasionally be compromised during the encryption or decryption process. While efforts are ongoing to address these issues, users are advised to maintain backups of their encrypted files and exercise caution when relying solely on EncryptXpert for data protection.

## Used By

This project is used by the following companies:

- SecureByte
- CQUPT


## FAQ

#### Question 1

Answer 1

#### Question 2

Answer 2


## API Reference

#### Get all items

```http
  GET /api/items
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `api_key` | `string` | **Required**. Your API key |

#### Get item

```http
  GET /api/items/${id}
```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `id`      | `string` | **Required**. Id of item to fetch |

#### add(num1, num2)

Takes two numbers and returns the sum.


## Contributing

Contributions are always welcome!

See `contributing.md` for ways to get started.

Please adhere to this project's `code of conduct`.


## 🚀 About Me
I'm a full stack developer...


## License

[MIT](https://choosealicense.com/licenses/mit/)

