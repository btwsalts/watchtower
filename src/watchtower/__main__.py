"""Run Watchtower using Python module startup."""

import uvicorn

if __name__ == "__main__":
    uvicorn.run("watchtower.main:app", host="127.0.0.1", port=8000, reload=True)
