# ☁️ Cloud Infrastructure Provisioning System

This repository contains the architecture and codebase for a custom infrastructure provisioning platform. The system lets authenticated users generate, store, and retrieve Terraform (`.tf`) and JSON configuration files through a web interface.

## 🏗️ Architecture Overview

The environment runs on AWS inside a custom VPC, using a public subnet and an Internet Gateway and Route Table for external routing. I built the platform using a microservices approach distributed across three dedicated EC2 instances:

**1. Frontend (React + Nginx + Cloudflare)**
* Hosts the web interface under the custom domain `afekio.com`.
* Integrates Cloudflare Zero Trust for secure, authenticated access to the application.
* Uses Cloudflare WAF (Web Application Firewall) to block malicious traffic before it reaches the AWS environment.
* Enforces strict HTTPS encryption using a Cloudflare-provisioned SSL certificate.
* Nginx acts as an internal reverse proxy, taking the clean traffic from Cloudflare and routing API calls to the correct backend server based on the URL path.

**2. Provisioning Backend (Python + Flask + Boto3)**
* Takes the user's infrastructure requirements and validates the input.
* Compiles the actual `.tf` or `.json` files.
* Uploads the generated files directly to an Amazon S3 bucket.
* Sends an internal POST request to the Auth server to log the new file's S3 path.

**3. Auth & Metadata Service (Python + Flask + SQLAlchemy + Boto3)**
* Handles user sign-ups and JWT-based logins.
* Connects to an Amazon RDS (PostgreSQL) database to store user profiles and file metadata.
* Uses Boto3 to fetch the raw file content directly from S3 when a user wants to view or download their past work.
* Triggers critical error alerts to an administrator email list via AWS SNS.
---

## 🌩️ AWS Services Used

| Service | Purpose |
| :--- | :--- |
| **S3** 🪣 | Object storage for the generated configuration files. |
| **RDS** 🗄️ | Managed PostgreSQL database for user credentials and file paths. |
| **SNS** 📨 | Push notifications for critical system errors (routes directly to email). |

---

## 🛡️ Security Posture

I locked down the environment using strict networking rules and identity management to avoid relying on hardcoded credentials.

**Security Groups**
* **Frontend:** Inbound HTTP (`80`) and HTTPS (`443`) traffic is strictly limited to Cloudflare's verified IP ranges. Direct public access to the EC2 instance is denied, guaranteeing that all requests are inspected by the Cloudflare WAF and Zero Trust policies before reaching Nginx.
* **Provisioning:** Accepts inbound traffic on port `5000` from the Frontend's SG. It also initiates connections to the Auth server on port `5001` for internal data sync.
* **Auth:** Only accepts traffic on port `5001` from the Frontend and Provisioning servers' SGs.
* **RDS:** Restricted to port `5432`, allowing connections exclusively from the Auth server.

**IAM Roles**
The backend EC2 instances use attached IAM roles instead of access keys:
* The Provisioning server has a policy allowing `s3:PutObject` for the specific bucket.
* The Auth server has a policy allowing `s3:GetObject` for the bucket and `sns:Publish` for the alert topic.

---

## 🔄 How It Works

**Generating a File**
User clicks 'Create' ➡️ React App ➡️ Nginx ➡️ Provisioning EC2 ➡️ Uploads to S3 ➡️ Notifies Auth EC2 ➡️ Saves metadata in RDS.

**Retrieving a File**
User clicks 'View' ➡️ React App ➡️ Auth EC2 ➡️ Looks up path in RDS ➡️ Pulls content from S3 ➡️ Returns to UI.

**System Alerts**
Auth EC2 catches an exception (e.g., DB down) ➡️ Triggers SNS Topic ➡️ Sends email alert to admins.

## Architecture Diagram
![Architecture Diagram](My-app.drawio.svg)