# burp-hash

Burp-hash is a Burp Suite plugin. 

Many applications will hash parameters such as ID numbers and email addresses for use in secure tokens, like session cookies. The plugin will passively scan requests looking for hashed values. Once a hashed value is found, it is compared to a table of parameters already observed in the application to find a match. The plugin keeps a lookout for parameters such as usernames, email addresses, and ID numbers. It also keeps a lookout for hashes (SHA, MD5, etc). It hashes new data and compares to observed hashes. The user receives a notification if any hashes match. This automates the process of trying to guess common parameters used in the generation of hashes observed in an application.

Here is a brief video that explains the concept: https://youtu.be/KdgeipzmESE

### Release

We are pleased to announce burp-hash has been accepted for [Black Hat USA Arsenal 2015](https://www.blackhat.com/us-15/arsenal.html#burp-hash). Following the presentation at Black Hat, the software will be released to the public here on GitHub.


### Created by

* Scott Johnson
* Tim MalcomVetter
* Matt South
