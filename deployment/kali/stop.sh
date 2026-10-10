#!/usr/bin/env bash
pkill -f 'gunicorn.*app:app' || true
