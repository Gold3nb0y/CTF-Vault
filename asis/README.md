# Asis

From this CTF I managed to solve backdooredness after the CTF had finished.
I upsolved with the piece of information I was missing from during the CTF, how to arb read.

In retrospect, there are 2 things I should have focused on:

1. compiling from C from the start (I spent the first 8 hours using assembly which slowed my development speed)
2. examining ALL program sections that interact with memory. I only focused on the MainBus and not the Picture MainBus

Once I learned how the Arb read vuln was preformed I was able to develop the exploit by myself!
Overall, it was a great challenge and I learned a lot about NES development.
