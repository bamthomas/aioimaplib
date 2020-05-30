#!/bin/bash
# -*- coding: UTF8 -*-

python setup.py bdist_wheel sdist bdist_egg 
twine upload dist/*
