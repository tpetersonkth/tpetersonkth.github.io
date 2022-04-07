---
layout: post
title:  "OSWE Review 2022"
date:   2000-01-01 07:00:00 +0200
tags: ["OSWE"]
---
{% assign imgDir="OSWE-Review" %}

# Introduction

In December last year, I decided to start studying for the Offensive Security Web Expert (OSWE) certification. This certificate is given to anyone who passes the exam related to the Advanced Web Attacks Eploitation (AWAE) course provided by Offensive Security. I bought 90 days of access to the AWAE course and got started the 11th december. Prior to this, I had around 1 year and 9 months of experience working with penetration testing. Most of my penetration tests concerned web applications and were performed as white-box penetration tests, meaning that I had the source code available while testing. As such, I was reasonably familiar with navigating large code bases in order to find vulnerabilites. 

In Mars, I attempted and passed the exam on my first attempt. The goal of this post is to help anyone who hasn't started their OSWE journey yet or is in the middle of it. In this post, I will describe my journey and provide tips on how to get the most out of the AWAE course. I won't disclose any information concerning what the lab exercises and extra miles are about, as Offensive Security forbids this. In addition, I won't provide any information concerning the exam machines, for obvious reasons. I will, however, present how much time I spent on different course related activities and present a set of tips for getting the most out of the AWAE course which could increase the probability of passing the OSWE exam. 

# My Journey

Before staring the course, I purchased a [Hack The Box](https://www.hackthebox.com/) subscription and did all of the OSWE machines in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). My lab access started the 11th December and ended the 11th Mars. I then took 2 weeks of rest before attempting the exam to ensure that I would have enough energy to work despise potential sleep deprivation. The course consisted of a long course book together with videos, exercises and extra miles exercises for each chapter. My approch was to take one chapter at a time. This mean reading the chapter, watching the related videos and finsihing the regular exercises. Once I was done with all the exercises, I started with the extra miles exercises. Together with the course book, Offensive Security also provided a set of lab machines. How to hack all of these except for three, were more or less covered in the course material. 

The longest I was stuck on an extra miles was 3 days. When stuck, I found the best approach to be to take a break before retrying. Just like the OSCP, the OSWE course (AWAE) came with access to a community forum where other students could share hints on how to solve the exercises and extra miles. As such, when completely stuck, it was possible to find other students who could hint you towards the right direction, making it slightly easier. To ensure that I was learning as much as possible, I avoided looking at hints unless I had been completely stuck on an extra miles for atleast two days, as I believed that this approach would force me to grow.

While I did a lot of studying during evenings and weekends, my job also gave me some time to study during the time periods 13/12 to 23/12, 3/1 to 11/1 and 17/1 to 31/1. During these day, I spent on average approximately one or two hours a day working on tasks related to my job, and the remainder of the day on the course. I would almost always start at 9.00 and finish no later than 21.00. I tried to always stop working at 21.00 since it normally doesn't help me to work for longer since I just get more tired and unproductive the next day.

The table below shows how I spent each day of my lab access. Note that this table includes 91 days since it contains 89 full days and 2 half-days. In the beginning, I tried to finish a chapter per day. This included reading the course book, watching the related videos, taking notes and completing the exercises, but not the extra miles exercises. Since some chapters were longer or shorter as well as easier or harder, I would sometimes get stuck a bit longer on some of them. 

<!-- 
| 41 | 20/1 | Chapter x | 3 |  | 
| 42 | 21/1 | Chapter x | 3 |  | 
| 43 | 22/1 | Chapter x | 3 |  | 
| 44 | 23/1 | Chapter x | 3 |  | 
| 45 | 24/1 | Chapter x | 3 |  | 
| 46 | 25/1 | Chapter x | 3 |  | 
| 47 | 26/1 | Chapter x | 3 |  | 
| 48 | 27/1 | Chapter x | 3 |  | 
| 49 | 28/1 | Chapter x | 3 |  | 
| 50 | 29/1 | Chapter x | 3 |  | 
| 51 | 30/1 | Chapter x | 3 |  | 
| 52 | 31/1 | Chapter x | 3 |  | 
| 53 | 1/2 | Chapter x | 3 |  | 
| 54 | 2/2 | Chapter x | 3 |  | 
| 55 | 3/2 | Chapter x | 3 |  | 
| 56 | 4/2 | Chapter x | 3 |  | 
| 57 | 5/2 | Chapter x | 3 |  | 
| 58 | 6/2 | Chapter x | 3 |  | 
| 59 | 7/2 | Chapter x | 3 |  | 
| 60 | 8/2 | Chapter x | 3 |  | 
| 61 | 9/2 | Chapter x | 3 |  | 
| 62 | 10/2 | Chapter x | 3 |  | 
| 63 | 11/2 | Chapter x | 3 |  | 
| 64 | 12/2 | Chapter x | 3 |  | 
| 65 | 13/2 | Chapter x | 3 |  | 
| 66 | 14/2 | Chapter x | 3 |  | 
| 67 | 15/2 | Chapter x | 3 |  | 
| 68 | 16/2 | Chapter x | 3 |  | 
| 69 | 17/2 | Chapter x | 3 |  | 
| 70 | 18/2 | Chapter x | 3 |  | 
| 71 | 19/2 | Chapter x | 3 |  | 
| 72 | 20/2 | Chapter x | 3 |  | 
| 73 | 21/2 | Chapter x | 3 |  | 
| 74 | 22/2 | Chapter x | 3 |  | 
| 75 | 23/2 | Chapter x | 3 |  | 
| 76 | 24/2 | Chapter x | 3 |  | 
| 77 | 25/2 | Chapter x | 3 |  | 
| 78 | 26/2 | Chapter x | 3 |  | 
| 79 | 27/2 | Chapter x | 3 |  | 
| 80 | 28/2 | Chapter x | 3 |  | 
| 81 | 1/3 | Chapter x | 3 |  | 
| 82 | 2/3 | Chapter x | 3 |  | 
| 83 | 3/3 | Chapter x | 3 |  | 
| 84 | 4/3 | Chapter x | 3 |  | 
| 85 | 5/3 | Chapter x | 3 |  | 
| 86 | 6/3 | Chapter x | 3 |  | 
| 87 | 7/3 | Chapter x | 3 |  | 
| 88 | 8/3 | Chapter x | 3 |  | 
| 89 | 9/3 | Chapter x | 3 |  | 
| 90 | 10/3 | Chapter x | 3 |  | 
| 91 | 11/3 | Chapter x | 3 |  | 
-->


| Day | Date | Main Focus | Hours Worked (Estimate) | Comment |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| 1 | 11/12 | Planning | 5 | Started the course in the middle of the day | 
| 2 | 12/12 | Chapter 1/2 | 10 |  | 
| 3 | 13/12 | Chapter 3 | 10 |  | 
| 4 | 14/12 | Chapter 4 | 10 |  | 
| 5 - 6 | 15/12 - 16/12 | Chapter 5 | 20 | Struggled a bit | 
| 7 | 17/12 | Chapter 6/7 | 10 |  | 
| 8 | 18/12 | Chapter 7 | 10 |  | 
| 9 | 19/12 | Chapter 8 | 10 |  | 
| 10 | 20/12 | Chapter 9 | 10 |  | 
| 11 | 21/12 | Chapter 10 | 10 |  | 
| 12 | 22/12 | Chapter 11 | 10 |  | 
| 13 | 23/12 | Chapter 12 | 10 |  | 
| 14 | 24/12 | Christmas | 0 | Swedish Christmas celebration |
| 15 - 20 | 25/12 - 30/12  | Family | 0 | Holidays
| 21 | 31/12 | New Years Eve | 0 |  | 
| 22 - 25 | 1/1 - 4/1 | Chapter 13 | 32 | Felt tired and confused | 
| 26 | 5/1 | Break day | 0 | Working out, resting e.t.c |
| 27 | 6/1 | Extra chapter | 8 | Archived chapter available in the portal |
| 28 | 7/1 | Reading forums and planning | 5 |  |
| 29 - 32 | 8/1 - 11/1| Extra miles | 40 | Started working on extra miles |
| 33 - 35 | 12/1 - 14/1 | Work | 6 | Extra miles during evenings | 
| 36 - 52 | 15/1 - 31/1| Extra miles  | 165 |  |
| 53 - 56 | 1/2 - 4/2 | Work | 8 | Extra miles during evenings | 
| 57 - 58 | 5/2 - 6/2 | Extra miles | 20 |  |
| 59 - 63 | 7/2 - 11/2 | Work | 10 | Extra miles during evenings |
| 64 - 65 | 12/2 - 13/2 | Extra miles | 20 | All extra miles done! |
| 66 - 70| 14/2 - 18/2 | Work | 10 | Planning & methodology evaluation | 
| 71 | 19/2 | Blackbox machine | 10 |  |
| 72 | 20/2 | Whitebox machine 1 | 10 |  |
| 73 - 77 | 21/2 - 25/2 | Work | 0 | Resting after work |
| 78 - 79 | 26/2 - 27/2 | Whitebox machine 2 | 20 |  |
| 80 - 84 | 28/2 - 4/3 | Work | 10 | Figuring out Remote debugging | 
| 85 - 86 | 5/3 - 6/3 | Extra vulns from [forum post](https://forums.offensive-security.com/showthread.php?32421-Extra-Extra-Miles) | 20 |  |
| 87 - 91 | 7/3 - 11/3 | Work | 10 | Reviewing notes |

Between the 11/12 and the 6/1, I was finishing almost one chapter per day except for the holidays. I then spent a day partly resting and planning when to do what. This planning took some time since I was reading all the extra miles and assigning them a difficulty rating of Easy, Medium or Hard depending on how difficult it would be for someone with my background to finish them. This helped me know what I should expect. After the planning, I spent the days a total of approximately 269 hours, between 8/1 and 13/2, finishing all the extra miles. This number of hours is slightly inflated since I would sometimes tweak the extra miles exercises a little bit to see if I could manage to do them under different constraints.

Once I had finished the extra miles, I focused on the three extra machines that were barely metioned in the course material. These were 1 machine where I did not have source code access and 2 where I did have source code access. Thereafter, I spent some time trying to figure out exactly how to perform remote debugging in the different languages which were incldued in the course, as this was something that was not always completely clear to me when encountering large code bases. Thereafter, I spent some time finding additional vulnerabilites that were not mentioned in the course material, but that students had mentioned in [the forums](https://forums.offensive-security.com/showthread.php?32421-Extra-Extra-Miles). Finally, the last couple of days, I reviewed my notes to ensure that I had not missed anything.

<img src="/assets/{{ imgDir }}/desk.jpg" width="60%" />

Once my lab access ended, I made sure to prepare a template for the exam report according to the [exam guide](https://help.offensive-security.com/hc/en-us/articles/360046869951-OSWE-Exam-Guide). In addition, I prepared a camera form the proctoring, ensured that I had my passport available. To prepare for the exam, I had mounted the camera on a tripod since the proctorers needed to half of my body, as shown in the picture above. In addition, I had bought a lot of snacks which can be seen in the image below. I also prepared two extra sets of earphones, my passport and a pair of earplugs to have these easily available.

<img src="/assets/{{ imgDir }}/snacks.jpg" width="60%" />

Finally, I attempted the 48 hour exam (+24 hours for sending in the report) for the first time on Saturday 25/3 at 9 AM. I chose 9 AM since that was the time I would usually start working, hoping that my brain would feel like the exam was just regular lab work. I felt a bit nervous before doing the exam as I knew that I wasn't going to sleep much and expected to feel quite frustrated. However, thanks to all the preparation I had been doing, the exam was slightly easier than I expected and a lot of fun! After almost 70 hours with only 6 hours of sleep, I handed in my 58 pages long exam report (At 5:AM). Around 24 hours later, I received an email informing me that I had passed! :D

<img src="/assets/{{ imgDir }}/pass.png" width="80%" />

Apart from the lack of sleep during the exam, both the lab and the exam was an enjoyable experience. Looking back, I think that I made the right decision in taking the course, since it helped me sharpen my code review skills significantly. Additionally, the course material appeared to be quite well thought through and modern. Consequently, I would recommend anyone who is considering taking this course to just go for it.

# Tips and Checklist
In this section, I provide any tips I would give someone who has yet to do the OSWE. At the end of this section, I will include them in a checklist at the end of the section, making it easy to turn these into a todo list. 

Before starting the lab access, I recommend that you familiarize yourself with the languages which the course is focusing on. As can be seen in the [course syllabus](https://www.offensive-security.com/documentation/awae-syllabus.pdf), this is Java, C#, NodeJS and PHP. Learning how routing works for web applications in these languages is an essential skill for identifying exploitable vulnerabilities. In addition, I would also recommend hacking all of the machines mentioned in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979).

During the course, you will have to script a lot of automated exploitation using Python. Since this is a web course, you will need a Python module for sending web requests. I recommend getting familiar with the [requests](https://docs.python-requests.org/en/latest/) module. An example of automated exploitation with Python and this module, can be found [here]({% post_url 2022-04-02-HTB-Holiday-Automated-Exploitation %}). In addition, I strongly recommend getting reasonably good at regular expressions as these can be useful in a large amount of different contexts. An amazing site for playing around with regular expressions is [regex101](https://regex101.com/), as demonstrated below where a regex is used to search for SQLI vulnerabilities.

<img src="/assets/{{ imgDir }}/regex.png" width="80%" />

Once your lab access have started, I recommend taking the approach I ended up taking, which was to read a chapter, watch its corresponding videos and then doing the chapter's exercises. While doing this, you should take a lot of notes. I recommend using [cherrytree](https://www.giuspen.com/cherrytree/) to organize your notes as this makes it really quick to find what you need when you need it, later on. Once you have detailed notes of what you have learn for each chapter, I recommend proceeding with the extra miles. Some of the extra miles will force you to search for vulnerabilities without any guidance, which will force you to establish a methodology for how you approach secure code review. 

After finishing the extra miles, I recommend creating a draft methodology. I did this by making a cherrytree node for all different types of vulnerabilites and what I would search for to find them. Once you are happy with the methodology, you should proceed to apply it to the three extra lab machines, to see if it works in practice. 

If you still have lab access at this point, I recommend trying to find the vulnerabilties exists in the lab machines but weren't covered in the course material. A list of these can be found [here](https://forums.offensive-security.com/showthread.php?32421-Extra-Extra-Miles). When you have done these, or if your lab time is running out, you should check that you haven't forgotten anything in your notes. Finally, it is good to book an exam slot while you are still practicing in the lab, since exam slots normally need to be scheduled 2 or 3 months in advance.

After your lab access have ended, it is good if you try to dive deeper into subjects where you are still not feeling completely comfortable or where you are still feeling inexperienced. Furthermore, it is mentioned in the [official OSWE exam guide](https://help.offensive-security.com/hc/en-us/articles/360046869951-OSWE-Exam-Guide) that you should hand in a pentest report after your exam. I strongly recommend writing a template for this exam report before the exam starts, as you don't want to lost a bunch of time writing a pentest report from scratch. There are some good templates available [on github](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/). 

The last thing you should do before the exam is to relax! The exam is 3 days long, which could be quite energy consuming. Especially since it can be challenging to get good quality sleep during an exam. Finally, the listing below contains checklists of what you should do before, during and after the course, to ensure that you learn as much as possible. These checklists contain everything mentioned in this post.

{% highlight none linenos %}
Checklist Before Lab Access:
[X] Find this checklist
[] Get familiar with routing in Java, C#, NodeJS and PHP.
[] Do all the Hack the Box machines listed in TJnull's OSWE Preparation List: https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979
[] Familiarize yourself with the Python requests library: https://docs.python-requests.org/en/latest/
[] Learn regular expressions(regex) using https://regex101.com/

Checklist During Lab Access:
[] Read the course book, watch the videos and do the exercises while taking notes.
[] Do the extra miles.
[] Review the notes and establish a methodology (I.e how you search for different vulnerabilities)
[] Do the three extra lab machines with you methodology
[] Refine your methodology
[] There are more vulnerabilites in the lab machines than those mentioned in the exercises and extra miles of the course literature. See if you can find them (See the forums for hints: https://forums.offensive-security.com/showthread.php?32421-Extra-Extra-Miles )
[] Book the exam (Open slots are usually around 2 or 3 months away).
[] Check that nothing is missing from your notes (F.e something you learned during an extra mile e.t.c)

Checklist After Lab Access:
[] Review your notes and dive deeper into subjects where you don't feel super comfortable or experienced
[] Write a template report for the exam
[] Ensure that you have read the exam guide(https://help.offensive-security.com/hc/en-us/articles/360046869951-OSWE-Exam-Guide), have snacks ready, your passport ready and a camera that you can mount appropriately.
[] Make sure to relax before the exam.
{% endhighlight %}


