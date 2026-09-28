"""Server entry point for A1 DFIR Investigator Web UI."""
import argparse
from a1.web.server import start

def main():
    parser = argparse.ArgumentParser(description="A1 DFIR Web Interface")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()

    start(host=args.host, port=args.port, open_browser=not args.no_browser)

if __name__ == "__main__":
    main()
