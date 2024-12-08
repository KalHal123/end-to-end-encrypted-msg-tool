import os
import cryptography
import random

def getKey(key_location):
    with open(key_location, "r") as keyfile:
        return keyfile.read()

key = getKey(".key")