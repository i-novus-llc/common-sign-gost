#!/bin/bash

if [[ $TRAVIS_TAG == '' ]] ; then
  mvn clean install -B -U
else
  mvn --settings .travis/.maven.xml clean deploy -Prelease -B -U
fi