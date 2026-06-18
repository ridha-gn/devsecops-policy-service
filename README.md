# DevSecOps Policy-as-Code Service

Welcome to the DevSecOps Policy-as-Code Service. This project provides a robust, centralized engine for enforcing security policies across your infrastructure code before it ever reaches production.

We built this service to bridge the gap between security and engineering. Instead of relying on manual security reviews or late-stage vulnerability scanning, this system evaluates infrastructure configurations—such as Terraform, Dockerfiles, and Kubernetes manifests—in real-time against a comprehensive suite of security rules. 

## Key Features

- **Comprehensive Policy Engine:** Evaluates infrastructure code against over 100 built-in security policies, catching misconfigurations like hardcoded secrets, open network ports, and unencrypted storage.
- **Multi-Language Support:** Natively parses and analyzes Terraform (HCL), Dockerfiles, and Kubernetes YAML manifests.
- **Automated Remediation:** Not only identifies vulnerabilities but also includes an auto-fix mechanism to suggest or apply secure configurations automatically.
- **FastAPI Backend:** A highly performant RESTful API that handles scan requests, manages compliance metrics, and orchestrates the policy enforcement process.
- **IDE Integration:** A dedicated VS Code extension that brings policy validation directly into the developer environment, providing immediate feedback on save.
- **Monitoring and Observability:** Fully instrumented with Prometheus and Grafana to provide real-time dashboards detailing security posture, violation trends, and system health.
- **Role-Based Access Control:** Granular permission models ensuring clear separation of duties among developers, security engineers, and administrators.

## Architecture Highlights

The system operates on a modular microservices architecture:

1. **API Layer:** Handles incoming requests from CI/CD pipelines, CLI tools, and the IDE extension.
2. **Parser and Normalizer:** Translates raw infrastructure code into a standardized format for evaluation.
3. **Enforcement Engine:** Compares normalized code against the policy definitions to generate compliance reports.
4. **Data Layer:** Maintains scan history and aggregates compliance data for reporting.

## Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.9 or higher
- Docker and Docker Compose (for the monitoring stack)
- Node.js (if you intend to build or modify the VS Code extension)

## Getting Started

Follow these steps to get the service running locally on your machine.

### 1. Clone and Setup Environment

First, navigate to the project directory and create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 2. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### 3. Run the Service

You can start the FastAPI application using Uvicorn:

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`. You can access the interactive Swagger documentation at `http://localhost:8000/docs`.

### 4. Start the Monitoring Stack (Optional)

If you wish to view the Grafana dashboards and Prometheus metrics, spin up the monitoring stack using Docker Compose:

```bash
docker-compose up -d
```

## Usage Examples

Once the service is running, you can interact with it via the API. Here are a few common operations.

### Analyzing Code

You can submit infrastructure code for analysis by hitting the `/analyze` endpoint.

**Example: Scanning a Terraform Snippet**

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code_type": "terraform",
    "content": "resource \"aws_s3_bucket\" \"bad\" {\n  bucket = \"my-bucket\"\n  acl = \"public-read\"\n}"
  }'
```

The engine will return a JSON report detailing any security violations, such as the bucket having a public-read ACL.

### Retrieving Metrics

To get an overview of your security posture and system performance:

```bash
curl http://localhost:8000/metrics
```

We also include bash scripts (like `demo_complete.sh`) to help you run a full suite of test cases automatically and verify the system behavior.

## Project Structure

- `api/`: Routing, endpoints, and prometheus configurations.
- `engine/`: Core logic including the parser, normalizer, auto-fix mechanisms, and policy definitions.
- `models/`: Pydantic models for data validation and schema definitions.
- `tests/`: Automated test suites for the core engine and API endpoints.
- `vscode-extension/`: Source code for the IDE plugin.
- `config/`: Configurations for monitoring tools and external integrations.

## IDE Integration

To provide a seamless developer experience, we have included a VS Code extension in the `vscode-extension` directory. This extension connects to your local instance of the DevSecOps service and highlights policy violations directly in your editor as you type. Refer to the specific instructions within that directory for packaging and installing the extension locally.

## Testing

We use pytest to ensure the reliability of the policy engine and API. To run the test suite, simply execute:

```bash
pytest
```

## Conclusion

This service represents a proactive approach to security. By shifting left and validating infrastructure code at the source, we prevent misconfigurations from becoming production incidents. We hope this tool serves as a valuable asset in your DevSecOps pipeline.
