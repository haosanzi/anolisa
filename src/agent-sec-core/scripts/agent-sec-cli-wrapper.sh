#!/bin/bash
# Wrapper script for agent-sec-cli / agent-sec-daemon
# Sets PYTHONPATH to private site-packages to avoid conflicts with system RPM packages
PYTHONPATH=/opt/agent-sec/lib/python3.11/site-packages${PYTHONPATH:+:$PYTHONPATH}
case "$(basename "$0")" in
  agent-sec-daemon)
    exec python3 -c 'import sys; sys.argv[0] = "agent-sec-daemon"; from agent_sec_cli.daemon.server import main; sys.exit(main())' "$@"
    ;;
  agent-sec-cli|*)
    exec python3 -c 'import sys; sys.argv[0] = "agent-sec-cli"; from agent_sec_cli.cli import main; sys.exit(main())' "$@"
    ;;
esac
