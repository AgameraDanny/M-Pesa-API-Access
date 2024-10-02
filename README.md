# M-Pesa-API-Access
This Node.js application integrates M-Pesa payment services with user authentication. It supports user registration, login, STK push requests, withdrawals, and transaction status queries, all while providing secure file uploads for certificates. Built using Express.js, it facilitates seamless financial transactions.

## Overview

This project is a Node.js application designed to integrate with the M-Pesa payment system. It allows users to register, log in, and perform various M-Pesa transactions, including STK push and withdrawals. 

### Features

- User registration and authentication
- M-Pesa STK push functionality
- M-Pesa withdrawal transactions
- Transaction status querying
- Callback handling for M-Pesa transactions
- File upload support for certificates
- Basic error handling and logging

## Tech Stack

- Node.js
- Express.js
- Axios
- Multer (for file uploads)
- Body-parser
- CORS
- File System
- Crypto

### Prerequisites

- Node.js and npm installed on your machine.
- Access to the M-Pesa API (Sandbox or Live) with your consumer key and secret.
