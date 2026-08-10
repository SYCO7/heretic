# HERETIC — business-logic vulnerability agent (CLI).
# Lean image; the LLM brain is a remote free API (Nemotron/Gemini) or a local
# Ollama you run alongside. Playwright browsers (M2+ browser crawl) are optional.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir .

# For JS-heavy targets that need browser crawling, uncomment:
#   RUN pip install --no-cache-dir playwright && playwright install --with-deps chromium

# Point at a local Ollama for a fully-private run:  -e OLLAMA_HOST=http://host:11434
# Or a free API key:  -e NVIDIA_API_KEY=...   /   -e GEMINI_API_KEY=...
ENTRYPOINT ["heretic"]
CMD ["--help"]
