import os
import uvicorn

if __name__ == "__main__":
    # psycopg async needs a SelectorEventLoop. uvicorn on Windows defaults to ProactorEventLoop and
    # ignores asyncio event loop policies; a custom loop string is used as the loop factory.
    uvicorn.run("server.main:app", host="127.0.0.1", port=int(os.getenv("ACP_PORT", "8787")),
                loop="asyncio:SelectorEventLoop")
