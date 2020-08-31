#!/bin/bash

if [[ $TRAVIS_TAG == '' ]] ; then
  mvn --settings $TRAVIS_DIR/.maven.xml clean install -B -U
else
  openssl aes-256-cbc -pass pass:$ENCRYPTION_PASSWORD -in $TRAVIS_DIR/pubring.gpg.enc -out $TRAVIS_DIR/pubring.gpg -d
  openssl aes-256-cbc -pass pass:$ENCRYPTION_PASSWORD -in $TRAVIS_DIR/secring.gpg.enc -out $TRAVIS_DIR/secring.gpg -d
  mvn --settings $TRAVIS_DIR/.maven.xml clean deploy $TRAVIS_DIR/settings.xml -Prelease -B -U
fi