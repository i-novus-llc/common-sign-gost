#!/bin/bash

if [[ $TRAVIS_TAG == '' ]] ; then
  mvn --settings $TRAVIS_DIR/.maven.xml clean install -B -U
else
  mvn --settings $TRAVIS_DIR/.maven.xml clean deploy $TRAVIS_DIR/settings.xml -Prelease -B -U
fi