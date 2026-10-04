# Setup and required artifacts

This guide describes the current snapshot. Full inference has not been verified, and this documentation update does not resolve the runtime or authorization issues below.

## 1. Inspect the release without installing the model stack

```bash
git clone https://github.com/Sandeep945-pixel/PrivAware.git
cd PrivAware
python scripts/check_artifacts.py
```

On Windows, `py` can be used in place of `python`. The checker uses only the Python standard library. Missing artifacts produce exit code `1`; a complete presence check produces `0`. Presence does not validate artifact contents.

## 2. Obtain the model assets

The service expects a local `new_fine_tuned_model/` directory containing a Transformers-compatible sequence-to-sequence checkpoint and its tokenizer. No checkpoint download URL is supplied in this release. Training scripts are also absent.

The related paper describes Flan-T5, but the runtime loads a generic `AutoModelForSeq2SeqLM` from the local directory. The exact model variant, training configuration, and compatibility must be established from the actual released checkpoint.

The checker recognizes ordinary or sharded PyTorch/Safetensors weight filenames and common tokenizer assets. It does not load or authenticate them.

## 3. Reconstruct the environment

`requirements.txt` preserves the existing pinned environment. Imports additionally require `faiss` and `sentence_transformers`; password hashing requires a bcrypt backend. Those runtime dependencies are not fully specified in the existing requirements file.

Before publishing a runnable demo, choose and test a compatible environment, record the missing dependency versions, and validate the checkpoint on the intended hardware. The code selects CUDA when available and otherwise CPU. Memory requirements depend on the missing model.

The existing OpenAI code uses the legacy `openai.ChatCompletion.create` interface and `gpt-4` identifier. Upgrading the SDK requires adapting that code; a current SDK is not a drop-in replacement.

## 4. Resolve configuration and data boundaries

The configuration module reads `SECRET_KEY`, `OPENAI_API_KEY`, and `MONGO_URI`. However, `db/db.py` currently initializes `MongoClient` with an empty string rather than the configured URI. Setting the environment variable alone does not correct that connection.

Use a strong non-default signing secret, a dedicated synthetic database, and credentials restricted to that experiment. Review signup role assignment, query filters/projections, policy parsing, and sensitive logging before serving requests. See [limitations](LIMITATIONS.md).

The local FAISS index and pickle chunk mapping are loaded relative to the process working directory. Only load trusted pickle files. Rebuilding the index with `vector_indexing.py` requires the embedding model and may download assets; the offline checker does neither.

## API reference

| Method | Path | Input |
| --- | --- | --- |
| POST | `/auth/signup` | JSON containing username, password, and role; optional full name and email |
| POST | `/auth/login` | OAuth2 form fields `username` and `password` |
| POST | `/ask/ask` | JSON `question` with a bearer token |

The doubled `/ask/ask` path comes from the router prefix and endpoint path in the current code. After the prerequisites and security issues are addressed, the existing development entry point is `uvicorn main:app --host 127.0.0.1 --port 8000`, run from the repository root. This is not a verified end-to-end startup recipe for the present release.

[Back to PrivAware](../README.md)
