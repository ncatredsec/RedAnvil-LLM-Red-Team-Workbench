# REDANVIL AI - LLM Red-Team Workbench

# (FORGE. ATTACK. EVALUATE.)

## Installation, Configuration \& Getting Started Guide

Welcome to the LLM Red-Team Workbench!

This guide walks you through installing the workbench, configuring a local Ollama model, connecting to OpenAI, and getting started with adversarial LLM testing.

The workbench supports local and cloud-based AI models. You can use Ollama to run models locally or connect to OpenAI using an API key.



## Note – Flexible Setup Options



**You do not need to install or configure everything to use RedAnvil AI:**



**OpenAI only**: You can skip Ollama installation entirely if you prefer using OpenAI models through an API key. OpenAI models run remotely, so no local model hosting is required.



**Ollama only**: You can use locally hosted models through Ollama without connecting to OpenAI. This allows you to run AI models on your own machine.



**Both OpenAI and Ollama**: You can configure both providers and switch between cloud-based and locally hosted models whenever needed.



**Without AI integration**: You can also use RedAnvil AI without connecting any AI model. Core workbench features, including predefined and custom prompt mutations, can be used independently. However, AI-assisted features such as adversarial prompt improvisation and model-assisted response analysis will not be available.



Choose the setup that best suits your environment, available resources, and testing requirements.

\---

# 1\. Prerequisites

Before installing the workbench, ensure you have:

* Windows 10/11, macOS, or Linux.
* Python 3.10 or newer.
* Internet connectivity for downloading dependencies and models.
* Sufficient disk space and RAM for your selected local model.
* An OpenAI API key if you intend to use OpenAI models.

**Recommended local model:** Qwen3:8B

You can use OpenAI independently or alongside Ollama. You do not need an OpenAI API key to use the local Ollama provider.

\---

# 2\. Install Python

Download Python from:

https://www.python.org/downloads/

During Windows installation, enable:

**Add Python to PATH**

After installation, open PowerShell and verify:

```powershell
python --version
pip --version
```

You should see the installed Python and pip versions.

If `python` is not recognized, reopen PowerShell or check your PATH configuration.

\---

# 3\. Install Ollama

Ollama allows you to run supported AI models locally without requiring an external AI API.

Download Ollama:

https://ollama.com/download

Install the Windows version using the installer.

Once installation is complete, open PowerShell and verify:

```powershell
ollama --version
```

If Ollama is installed correctly, this command displays its version.

## 3.1 Download Qwen3:8B

Run:

```powershell
ollama pull qwen3:8b
```

This downloads the Qwen3 8B model to your machine.

Depending on your internet speed, this may take some time because the model download is several gigabytes.

Verify the downloaded model:

```powershell
ollama list
```

You should see `qwen3:8b` in the list.

## 3.2 Test the model

Start an interactive session:

```powershell
ollama run qwen3:8b
```

Try a simple prompt:

```text
Explain the difference between direct prompt injection and indirect prompt injection.
```

If you receive a response, your local model is working.

Exit the interactive session when finished.

## 3.3 Verify the Ollama API

Ollama normally exposes its local API at:

```text
http://127.0.0.1:11434
```

Verify connectivity:

```powershell
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

The response should contain the models available locally.

Keep Ollama running while using the workbench.

\---

# 4\. Install the LLM Red-Team Workbench

Download and extract the workbench release package.

Open PowerShell and navigate to the extracted folder.

For example:

```powershell
cd "$HOME\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Downloads\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\llm-red-team-workbench-release"
```

Adjust the directory if you extracted the package somewhere else.

## 4.1 Create a Python virtual environment

Run:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\.venv\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Scripts\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Activate.ps1
```

If PowerShell blocks script execution for this session, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment again:

```powershell
.\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\.venv\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Scripts\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\Activate.ps1
```

## 4.2 Install dependencies

Run:

```powershell
python -m pip install --upgrade pip
```

Then install the required packages:

```powershell
pip install -r requirements.txt
```

This installs the Python dependencies required by the workbench.

## 4.3 Start the workbench

Run:

```powershell
python llm\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_redteam\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_workbench.py
```

The Flask application should start locally.

Open the URL displayed in your terminal, normally:

```text
http://127.0.0.1:5000
```

You should now see the LLM Red-Team Workbench interface.

\---

# 5\. Configure Ollama in the Workbench

Once the application is running:

1. Open the model/provider configuration section.
2. Select **Ollama** as the provider.
3. Enter or select the model:

```text
qwen3:8b
```

4. Use the default Ollama endpoint:

```text
http://127.0.0.1:11434
```

5. Save the configuration if prompted.

You can now use Qwen3:8B for prompt generation, adversarial prompt improvisation, and model-assisted response analysis.

**Note:** The model must already be downloaded through Ollama before it can be used.

\---

# 6\. Configure OpenAI

The workbench also supports OpenAI models through the OpenAI API.

## 6.1 Obtain an API key

Visit:

https://platform.openai.com/api-keys

1. Sign in to your OpenAI Platform account.
2. Create a new API key.
3. Copy the generated key and store it securely.

API usage may incur charges depending on the selected model and your account's API billing configuration.

ChatGPT subscriptions and OpenAI API billing are separate.

## 6.2 Add the API key to the workbench

1. Open the workbench.
2. Navigate to the OpenAI configuration section.
3. Paste your API key.
4. Save the key.
5. Select an available OpenAI model.

The workbench stores the API key locally in:

```text
llm\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_redteam\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_data/openai\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_api\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_key.txt
```

The application can also remove the saved key through its configuration interface.

**Security recommendation:**

* Never share your API key.
* Do not commit the API key file to GitHub.
* Do not include API keys in screenshots or reports.
* Avoid exposing the workbench to untrusted networks.
* Rotate the key if it is accidentally disclosed.

\---

# 7\. Configure Burp Suite Proxy (Optional)

The workbench supports configurable proxy settings for provider API traffic.

This can be useful when you want to inspect model-provider requests and responses through Burp Suite.

Example configuration:

```text
Proxy Host: 127.0.0.1
Proxy Port: 8080
```

Start Burp Suite and configure its proxy listener accordingly.

Enable the proxy option in the workbench and enter the proxy address.

For HTTPS inspection, ensure your Python environment trusts the Burp CA certificate. Otherwise, TLS certificate verification may fail.

**Important:** This proxy configuration concerns traffic from the workbench to the AI provider. It does not automatically configure traffic to your target application.

\---

# 8\. Using the Workbench

The workbench provides several capabilities:

### Prompt mutation

Generate variations of an existing prompt using different adversarial techniques.

### Adversarial prompt improvisation

Provide the actual target scenario, original prompt, and desired attack strategy.

The selected AI model improvises a context-specific adversarial prompt rather than simply selecting from a fixed collection of examples.

### Model-assisted response analysis

Provide the prompt submitted to the target and the target's actual response.

The selected model analyses the observed behavior and recommends additional adversarial tests.

### Adaptive attack sessions

Create a named attack session and define its objective.

Each iteration can preserve:

* The adversarial prompt.
* The target's response.
* The model's analysis.
* The suggested next iteration.

The model receives previous session context so it can adapt its recommendations instead of repeatedly suggesting the same failed approach.

Target execution remains under the tester's control.

### Custom templates

Create and maintain reusable prompt templates for your assessments.

### Saved test cases

Save and revisit generated test cases and testing scenarios.

### Encrypted Prompt Mutation Testing (AES-GCM)

Test whether AI applications consistently enforce their security restrictions when processing encrypted and mutated prompts or generating encrypted responses.

This feature allows security testers to:

* Generate encrypted prompts containing mutated instructions.
* Evaluate whether encrypted instructions can bypass AI guardrails and security policies.
* Examine how the target application processes encrypted inputs and generates encrypted outputs.
* Identify inconsistencies in security-policy enforcement between plaintext and encrypted interactions.

**Objective:** Assess whether encryption-based prompt delivery can expose weaknesses in an AI application's guardrails, instruction handling, or security-policy enforcement.

\---

# 9\. Integrating Additional AI Models

**The workbench is designed to be extensible. You are not restricted to Qwen3 or OpenAI.**

You can integrate other AI models with the help of AI itself!

For example, suppose you want to add another model provider.

You can ask an AI coding assistant to:

1. Review the existing workbench source code.
2. Understand how the current Ollama and OpenAI integrations work.
3. Identify the provider-specific API requirements of the new model.
4. Implement the required provider configuration and API integration.
5. Add model selection to the user interface.
6. Handle authentication, request formatting, response parsing, and errors.
7. Preserve existing features and configuration options.
8. Test the new integration without breaking the existing providers.

### Example: Ask AI to integrate another model

You can use a prompt similar to this:

```text
I have an existing Flask-based LLM Red-Team Workbench.

Review the existing source code and understand how Ollama and OpenAI
providers are integrated.

I want to add support for \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\[MODEL / PROVIDER NAME].

Please:

1. Study the provider's official API documentation.
2. Implement the new provider using its supported API.
3. Add the provider and model selection options to the UI.
4. Implement authentication and API-key management where required.
5. Preserve the existing proxy configuration functionality.
6. Ensure compatibility with prompt generation, prompt improvisation,
   and model-assisted response analysis.
7. Do not remove or modify existing provider functionality unnecessarily.
8. Add appropriate error handling and configuration validation.
9. Test the integration and provide the complete updated source code.

Keep the existing application architecture and user interface consistent.
```

Possible integration targets include:

* Additional Ollama-compatible models.
* Other OpenAI-compatible API providers.
* Cloud-hosted model APIs.
* Self-hosted inference endpoints.
* Other model providers with custom API integrations.

The exact implementation depends on the provider's API, authentication mechanism, request format, and response structure.

**In short: if a model exposes an accessible API, we can investigate how to integrate it. We can even use AI to help us implement and test that integration.**

\---

# 10\. Troubleshooting

|Problem|Suggested resolution|
|-|-|
|`python` is not recognized|Reinstall Python or correct PATH|
|`ollama` is not recognized|Reinstall Ollama and reopen PowerShell|
|Model not found|Run `ollama pull qwen3:8b`|
|Ollama connection refused|Ensure Ollama is running and its API is accessible|
|OpenAI authentication error|Verify the API key and account API access|
|OpenAI quota or billing error|Check API usage limits and billing|
|Python dependency errors|Activate the virtual environment and rerun `pip install -r requirements.txt`|
|Proxy connection failure|Verify Burp listener settings and certificate trust|
|Local model responds slowly|Check available RAM, GPU support, and model size|

\---

# 11\. Security and Privacy Considerations

* The workbench is intended for authorized security assessments.
* Keep the application bound to localhost unless remote access is explicitly required.
* Local Ollama inference can keep model requests on your machine, but any data sent to OpenAI or another cloud provider is subject to that provider's data-handling policies.
* Treat target prompts, responses, session histories, and assessment evidence as potentially sensitive.
* Do not store secrets or production credentials in saved prompts or reports.
* Keep API keys and local assessment data out of source-control repositories.
* Obtain authorization before testing external AI applications.

\---

# 12\. Final Notes

The LLM Red-Team Workbench is an extensible project. Its capabilities are not limited to the models currently integrated.

You can experiment with different models, add new providers, improve attack strategies, introduce new analysis techniques, and extend the application with the assistance of AI coding tools.

**Happy Red Teaming!**

