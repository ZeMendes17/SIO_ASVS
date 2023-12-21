#!/bin/bash

if [ -d "../instance" ]; then
  rm -r "../instance/db_sec.sqlite"
fi

export FLASK_APP=__init__.py
export FLASK_DEBUG=1

flask run
