#!/bin/bash

su seed
cd
echo "10.9.0.6" > .rhosts
chmod 644 .rhosts
exit
exit