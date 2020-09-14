#!/bin/bash

if [[ $TRAVIS_TAG == '' ]] ; then
  mvn clean install -B -U
else
  openssl aes-256-cbc -K $encrypted_81c98acad902_key -iv $encrypted_81c98acad902_iv -in .travis/codesigning.asc.enc -out .travis/signingkey.asc -d
  gpg --fast-import .travis/signingkey.asc
  mvn --settings .travis/.maven.xml clean deploy -DskipTests=true -Prelease -B -U
fi