// server.js
const express = require("express");
const axios = require("axios");
const bodyParser = require("body-parser");
const cors = require("cors");
const fs = require("fs");
const crypto = require("crypto");
const request = require("request");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 3001;
const usersFilePath = "./users.json";

app.use(bodyParser.json());
app.use(cors());
app.use(express.static("public"));

// Multer for file uploads
const upload = multer({ dest: "uploads/" });

// Load users from JSON file
const loadUsers = () => {
  if (fs.existsSync(usersFilePath)) {
    const data = fs.readFileSync(usersFilePath);
    return JSON.parse(data);
  }
  return [];
};

// Save users to JSON file
const saveUsers = (users) => {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
};

// Hash password using crypto
const hashPassword = (password) => {
  return crypto.createHash("sha256").update(password).digest("hex");
};

// Register a new user
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();

  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(400).send("User already exists");
  }

  const hashedPassword = hashPassword(password);
  const user = { username, password: hashedPassword };
  users.push(user);
  saveUsers(users);

  res.status(201).send("User registered");
});

// Login a user
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();

  const user = users.find((user) => user.username === username);
  if (user && user.password === hashPassword(password)) {
    // In a real application, you should use JWT or session for auth
    res.json({ message: "Login successful" });
  } else {
    res.status(401).send("Invalid credentials");
  }
});

// Function to generate an access token using provided credentials
async function generateAccessToken(consumer_key, consumer_secret) {
  const url =
    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials";
  const auth =
    "Basic " +
    Buffer.from(`${consumer_key}:${consumer_secret}`).toString("base64");

  try {
    const response = await axios.get(url, {
      headers: { Authorization: auth },
    });
    return response.data.access_token;
  } catch (error) {
    throw error;
  }
}

// Endpoint to generate access token
app.post("/api/generate_access_token", async (req, res) => {
  const { consumer_key, consumer_secret } = req.body;

  if (!consumer_key || !consumer_secret) {
    return res
      .status(400)
      .json({ error: "Consumer key and consumer secret are required." });
  }

  try {
    const accessToken = await generateAccessToken(
      consumer_key,
      consumer_secret
    );
    res.json({ access_token: accessToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to generate access token." });
  }
});

// Helper function to format phone number
function formatPhoneNumber(phoneNumber) {
  if (phoneNumber.startsWith("0")) {
    return "254" + phoneNumber.slice(1);
  } else if (phoneNumber.startsWith("+254")) {
    return phoneNumber.slice(1);
  }
  return phoneNumber; // Return as-is if no formatting is needed
}

// Function to format the current date and time for M-Pesa request
function getCurrentTimeFormatted() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  const hours = String(now.getHours()).padStart(2, "0");
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const seconds = String(now.getSeconds()).padStart(2, "0");

  return `${year}${month}${day}${hours}${minutes}${seconds}`;
}

// POST Route to send STK Push
app.post("/api/send_stk_push", async (req, res) => {
  const {
    consumer_key,
    consumer_secret,
    amount,
    phoneNumber,
    accountReference,
    transactionDesc,
  } = req.body;

  if (
    !consumer_key ||
    !consumer_secret ||
    !amount ||
    !phoneNumber ||
    !accountReference ||
    !transactionDesc
  ) {
    return res.status(400).json({ error: "All fields are required." });
  }

  try {
    const accessToken = await generateAccessToken(
      consumer_key,
      consumer_secret
    );
    const formattedPhoneNumber = formatPhoneNumber(phoneNumber);
    const timestamp = getCurrentTimeFormatted();
    const password = new Buffer.from(
      "174379" +
        "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919" +
        timestamp
    ).toString("base64");

    request(
      {
        url: "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
        method: "POST",
        headers: { Authorization: "Bearer " + accessToken },
        json: {
          BusinessShortCode: "174379",
          Password: password,
          Timestamp: timestamp,
          TransactionType: "CustomerPayBillOnline",
          Amount: amount,
          PartyA: formattedPhoneNumber,
          PartyB: "174379",
          PhoneNumber: formattedPhoneNumber,
          CallBackURL: "https://m-pesa-api-access.onrender.com/callback",
          AccountReference: accountReference,
          TransactionDesc: transactionDesc,
        },
      },
      (error, response, body) => {
        if (error) {
          console.error(error);
          res.status(500).json({ error: "Failed to initiate STK push." });
        } else {
          res.status(200).json(body);
        }
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to generate access token." });
  }
});

// Route for STK push callback
app.post("/api/callback", async (req, res) => {
  console.log("STK PUSH CALLBACK");
  console.log("-----------------");
  console.log(req.body); // Log the request body

  // Extract data from the callback request
  const { Body } = req.body;
  const MerchantRequestID = Body.stkCallback.MerchantRequestID;
  const CheckoutRequestID = Body.stkCallback.CheckoutRequestID;
  const ResultCode = Body.stkCallback.ResultCode;
  const ResultDesc = Body.stkCallback.ResultDesc;

  if (ResultCode === 0) {
    console.log("Transaction was successful.");
    console.log(ResultDesc);

    const callbackData = Body.stkCallback.CallbackMetadata.Item;

    // Initialize variables to store the extracted values
    let amount, mpesaReceiptNumber, transactionDate, phoneNumber;

    // Loop through the items and assign the values to respective variables
    callbackData.forEach((item) => {
      switch (item.Name) {
        case "Amount":
          amount = item.Value;
          break;
        case "MpesaReceiptNumber":
          mpesaReceiptNumber = item.Value;
          break;
        case "TransactionDate":
          transactionDate = item.Value;
          break;
        case "PhoneNumber":
          phoneNumber = item.Value;
          break;
        default:
          break;
      }
    });

    // Log the extracted variables
    console.log("Amount:", amount);
    console.log("MpesaReceiptNumber:", mpesaReceiptNumber);
    console.log("TransactionDate:", transactionDate);
    console.log("PhoneNumber:", phoneNumber);

    // Prepare transaction data for logging
    const transactionData = {
      merchantRequestID: MerchantRequestID,
      checkoutRequestID: CheckoutRequestID,
      resultCode: ResultCode,
      resultDesc: ResultDesc,
      amount: amount,
      mpesaReceiptNumber: mpesaReceiptNumber,
      transactionDate: transactionDate,
      phoneNumber: phoneNumber,
      savedDate: new Date().toISOString(), // Current date and time in ISO format
    };

    // Log the transaction data (you can also save this data to a file or other storage)
    console.log("Transaction data:", transactionData);

    // Send success response
    res.sendStatus(200);
  } else {
    console.log("Transaction failed.");
    console.log("Result Code:", ResultCode);
    console.log("Result Description:", ResultDesc);
    res.sendStatus(400); // Indicate failure
  }
});

// Function to encrypt the password using the provided certificate
function encryptPassword(initiatorPassword, certificatePath) {
  const certificate = fs.readFileSync(certificatePath);
  return crypto
    .publicEncrypt(
      { key: certificate, padding: crypto.constants.RSA_PKCS1_PADDING },
      Buffer.from(initiatorPassword)
    )
    .toString("base64");
}

// Function to generate a unique originator conversation ID.
function generateOriginatorConversationID() {
  const randomPart = Math.random().toString(36).substr(2, 8);
  const timestampPart = Date.now().toString(36);
  return randomPart + "-" + timestampPart + "-1";
}

// POST Route for processing withdrawals.
app.post("/api/withdraw", upload.single("certificate"), async (req, res) => {
  const { consumer_key, consumer_secret, amount, phoneNumber, remarks } =
    req.body;

    console.log(req.body);

  if (
    !consumer_key ||
    !consumer_secret ||
    !amount ||
    !phoneNumber ||
    !remarks ||
    !req.file
  ) {
    return res.status(400).json({ error: "All fields are required." });
  }

  let formattedPhoneNumber = phoneNumber.startsWith("0")
    ? "254" + phoneNumber.slice(1)
    : phoneNumber.startsWith("+254")
    ? phoneNumber.slice(1)
    : phoneNumber;

  try {
    // Initiator password (unencrypted)
    const initiatorPassword = "Safaricom999!*!";
    const accessToken = await generateAccessToken(
      consumer_key,
      consumer_secret
    );
    const securityCredential = encryptPassword(
      initiatorPassword,
      req.file.path
    );
    const uniqueID = generateOriginatorConversationID();

    const url = "https://sandbox.safaricom.co.ke/mpesa/b2c/v3/paymentrequest";
    const auth = "Bearer " + accessToken;

    request(
      {
        url: url,
        method: "POST",
        headers: { Authorization: auth },
        json: {
          OriginatorConversationID: uniqueID,
          InitiatorName: "testapi",
          SecurityCredential: securityCredential,
          CommandID: "PromotionPayment",
          Amount: amount,
          PartyA: "600980",
          PartyB: formattedPhoneNumber,
          Remarks: remarks,
          QueueTimeOutURL: "https://mydomain.com/b2c/queue",
          ResultURL: "https://m-pesa-api-access.onrender.com/api/withdraw/result",
          Occasion: "Withdrawal",
        },
      },
      (error, response, body) => {
        if (error) {
          console.log("Request error:", error);
          return res.status(500).json({ error: "Request failed." });
        }
        console.log("Request body:", body);
        return res.status(200).json(body);
      }
    );
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

/**
 * POST Route for handling the results of the B2C transaction.
 * Endpoint: /api/withdraw/result
 * Expected request body format:
 * {
 *   "Result": {
 *     "ResultType": "Type",
 *     "ResultCode": "Code",
 *     "ResultDesc": "Description",
 *     "TransactionID": "ID",
 *     "OriginatorConversationID": "ID"
 *   }
 * }
 *
 * This endpoint receives the response from the Safaricom API after a withdrawal
 * request has been processed. It logs the transaction results and handles success
 * or failure cases accordingly.
 */
app.post("/api/withdraw/result", (req, res) => {
  const result = req.body.Result;

  if (!result) {
    return res.status(400).json({ error: "Result object is required." });
  }

  const resultType = result.ResultType;
  const resultCode = result.ResultCode;
  const resultDesc = result.ResultDesc;
  const transactionID = result.TransactionID;
  const originatorConversationID = result.OriginatorConversationID;

  console.log("Received withdrawal result:");
  console.log("Result Type:", resultType);
  console.log("Result Code:", resultCode);
  console.log("Result Description:", resultDesc);
  console.log("Transaction ID:", transactionID);
  console.log("Originator Conversation ID:", originatorConversationID);

  if (resultCode === "0") {
    console.log("Transaction Successful:");
    // Handle successful transaction (e.g., log to database or notify the user)
  } else {
    console.error(`Transaction failed: ${resultDesc}`);
    // Handle failure (e.g., log to database or notify the user)
  }

  res.sendStatus(200); // Send success response
});

// POST Route for querying transaction status.
app.post("/api/transaction_status", upload.single("certificate"), async (req, res) => {
    console.log("herre");
    const { consumerKey, consumerSecret, transactionId } = req.body;

    console.log(req.body);

    if (!consumerKey || !consumerSecret || !transactionId || !req.file) {
      return res.status(400).json({ error: "All fields are required." });
    }

    try {
      // Generate access token
      const accessToken = await generateAccessToken(
        consumerKey,
        consumerSecret
      );

      // Encrypt the security credential using the uploaded certificate
      const initiatorPassword = "Safaricom999!*!"; // Your actual initiator password
      const securityCredential = encryptPassword(
        initiatorPassword,
        req.file.path
      );

      const url =
        "https://sandbox.safaricom.co.ke/mpesa/transactionstatus/v1/query";

      const requestBody = {
        Initiator: "testapi",
        SecurityCredential: securityCredential,
        CommandID: "TransactionStatusQuery",
        TransactionID: transactionId,
        PartyA: "600979", // Replace with your PartyA
        IdentifierType: "4",
        ResultURL: "https://m-pesa-api-access.onrender.com/api/transaction_status/result",
        QueueTimeOutURL: "https://yourdomain.com/TransactionStatus/queue/",
        Remarks: "Ok",
        Occasion: "",
      };

      request(
        {
          url,
          method: "POST",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
          json: requestBody,
        },
        (error, response, body) => {
            console.log(body);
          if (error) {
            console.error("Request error:", error);
            return res
              .status(500)
              .json({ error: "Failed to query transaction status." });
          }
          res.status(200).json(body);
        }
      );
    } catch (error) {
      console.error("Error:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);

// POST Route for handling the results of the transaction status query.
app.post("/api/transaction_status/result", (req, res) => {
  const result = req.body.Result;

  if (result) {
    console.log("Transaction Status Result Received:");
    console.log("Conversation ID:", result.ConversationID);
    console.log("Originator Conversation ID:", result.OriginatorConversationID);
    console.log("Result Code:", result.ResultCode);
    console.log("Result Description:", result.ResultDesc);
    console.log("Transaction ID:", result.TransactionID);

    if (result.ResultParameters && result.ResultParameters.ResultParameter) {
      result.ResultParameters.ResultParameter.forEach((param) => {
        console.log(`Key: ${param.Key}, Value: ${param.Value || "N/A"}`);
      });
    }

    // Handle the result further if needed

    res.sendStatus(200); // Respond with success
  } else {
    console.error("Invalid result data");
    res.status(400).json({ error: "Invalid result data" });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
