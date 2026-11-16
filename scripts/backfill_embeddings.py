import os

import psycopg

from server.embed import embed, to_pgvector

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://acp:acp@127.0.0.1:5435/acp")


def main() -> None:
    with psycopg.connect(DATABASE_URL) as conn:
        rows = conn.execute(
            "SELECT id, tool_name, summary FROM approvals WHERE embedding IS NULL"
        ).fetchall()

    with psycopg.connect(DATABASE_URL) as conn:
        for aid, tool_name, summary in rows:
            vector = embed(f"{tool_name}: {summary}")
            conn.execute(
                "UPDATE approvals SET embedding = %s::vector WHERE id = %s",
                (to_pgvector(vector), aid),
            )
            print(f"Embedded approval {aid}")


if __name__ == "__main__":
    main()
