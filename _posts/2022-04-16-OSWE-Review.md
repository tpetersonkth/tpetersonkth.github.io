---
layout: post
title:  "OSWE Review 2022"
date:   2022-04-16 07:00:00 +0200
#mainTags: ["OSWE"]
tags: ["C#","Certification Review","Hack The Box","Java","NodeJS","OSWE","PHP","Regular Expression"]
---
{% assign imgDir="2022-04-16-OSWE-Review" %}

# Introduction

In December last year, I decided to start studying for the Offensive Security Web Expert (OSWE) certification. This certificate is given to anyone who passes the exam corresponding to the Advanced Web Attacks Eploitation (AWAE) course provided by Offensive Security. I bought 90 days of access to the AWAE course and got started the 11th December. Prior to this, I had around 1 year and 9 months of experience working with penetration testing. Most of my penetration tests concerned web applications and were performed as white-box penetration tests, meaning that I had the source code available while testing. As such, I was reasonably familiar with navigating large code bases in order to find vulnerabilites. 

<img src="/assets/{{ imgDir }}/OSWE.png" width="40%" style="border: none;" />

In Mars, I attempted and passed the exam on my first attempt. In this post, I will describe my journey and provide tips on how to get the most out of the AWAE course. I won't disclose any information concerning what the lab exercises and extra miles are about, as Offensive Security forbids this. In addition, I won't provide any information concerning the exam machines, for obvious reasons. I will, however, present how much time I spent on different course related activities and present a set of tips for getting the most out of the AWAE course which could increase the probability of passing the OSWE exam. 

# My Journey

Before staring the course, I purchased a [Hack The Box](https://www.hackthebox.com/) subscription and did all of the OSWE machines in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). My lab access started the 11th December and ended the 11th Mars. I then took 2 weeks of rest before attempting the exam to ensure that I would have enough energy to work despise potential sleep deprivation. The course consisted of a long course book together with videos, exercises and extra miles exercises for each chapter. My approach was to try to finish one chapter at a time. This meant reading the chapter, watching the related videos and doing the related exercises. Once I was done with all the exercises, I started with the extra miles exercises. Together with the course book, Offensive Security also provided a set of lab machines. How to hack all of these except for three, were more or less covered in the course material. 

The longest I was stuck on an extra miles exercise was 3 days. When stuck, I found the best approach to be to take a break before retrying. Just like the OSCP, the OSWE course (AWAE) came with access to a community forum where other students could share hints on how to solve the exercises and extra miles. As such, when completely stuck, it was possible to find other students who could hint you towards the right direction, making it slightly easier. To ensure that I was learning as much as possible, I avoided looking at hints unless I had been completely stuck on an extra miles for atleast two days, as I believed that this approach would force me to grow.

While I did a lot of studying during evenings and weekends, my job also gave me some time to study during the time periods 13/12 to 23/12, 3/1 to 11/1 and 17/1 to 31/1. During these day, I spent on average approximately one or two hours a day working on tasks related to my job, and the remainder of the day on the course. I would almost always start at 9.00 and finish no later than 21.00. I tried to always stop working before 21.00 since it normally doesn't help me to work for longer as I just get tired and unproductive the next day.

The table below shows how I spent each day of my lab access. Note that this table includes 91 days since it contains 89 full days and 2 half-days. In the beginning, I tried to finish a chapter per day. This included reading the course book, watching the related videos, taking notes and completing the exercises, but not the extra miles exercises. Since some chapters were longer or shorter as well as easier or harder, I would sometimes get stuck a bit longer on them. 

<table class="customTable"><tr><th>Day</th><th>Date</th><th>Main Focus</th><th>Estimated Hours</th><th>Comment</th></tr>
<tr><td>1</td><td>11/12</td><td>Planning</td><td>5</td><td>Started the course in the middle of the day</td></tr>
<tr><td>2</td><td>12/12</td><td>Chapter 1/2</td><td>10</td><td></td></tr>
<tr><td>3</td><td>13/12</td><td>Chapter 3</td><td>10</td><td></td></tr>
<tr><td>4</td><td>14/12</td><td>Chapter 4</td><td>10</td><td></td></tr>
<tr><td>5 - 6</td><td>15/12 - 16/12</td><td>Chapter 5</td><td>20</td><td>Struggled a bit</td></tr>
<tr><td>7</td><td>17/12</td><td>Chapter 6/7</td><td>10</td><td></td></tr>
<tr><td>8</td><td>18/12</td><td>Chapter 7</td><td>10</td><td></td></tr>
<tr><td>9</td><td>19/12</td><td>Chapter 8</td><td>10</td><td></td></tr>
<tr><td>10</td><td>20/12</td><td>Chapter 9</td><td>10</td><td></td></tr>
<tr><td>11</td><td>21/12</td><td>Chapter 10</td><td>10</td><td></td></tr>
<tr><td>12</td><td>22/12</td><td>Chapter 11</td><td>10</td><td></td></tr>
<tr><td>13</td><td>23/12</td><td>Chapter 12</td><td>10</td><td></td></tr>
<tr><td>14</td><td>24/12</td><td>Christmas</td><td>0</td><td>Swedish Christmas celebration</td></tr>
<tr><td>15 - 20</td><td>25/12 - 30/12</td><td>Family</td><td>0</td><td>Holidays</td></tr>
<tr><td>21</td><td>31/12</td><td>New Years Eve</td><td>0</td><td></td></tr>
<tr><td>22 - 25</td><td>1/1 - 4/1</td><td>Chapter 13</td><td>32</td><td>Felt tired and confused</td></tr>
<tr><td>26</td><td>5/1</td><td>Break day</td><td>0</td><td>Working out, resting e.t.c</td></tr>
<tr><td>27</td><td>6/1</td><td>Extra chapter</td><td>8</td><td>Archived chapter available in the portal</td></tr>
<tr><td>28</td><td>7/1</td><td>Reading forums and planning</td><td>5</td><td></td></tr>
<tr><td>29 - 32</td><td>8/1 - 11/1</td><td>Extra miles</td><td>40</td><td>Started working on extra miles</td></tr>
<tr><td>33 - 35</td><td>12/1 - 14/1</td><td>Work</td><td>6</td><td>Extra miles during evenings</td></tr>
<tr><td>36 - 52</td><td>15/1 - 31/1</td><td>Extra miles</td><td>165</td><td></td></tr>
<tr><td>53 - 56</td><td>1/2 - 4/2</td><td>Work</td><td>8</td><td>Extra miles during evenings</td></tr>
<tr><td>57 - 58</td><td>5/2 - 6/2</td><td>Extra miles</td><td>20</td><td></td></tr>
<tr><td>59 - 63</td><td>7/2 - 11/2</td><td>Work</td><td>10</td><td>Extra miles during evenings</td></tr>
<tr><td>64 - 65</td><td>12/2 - 13/2</td><td>Extra miles</td><td>20</td><td>All extra miles done!</td></tr>
<tr><td>66 - 70</td><td>14/2 - 18/2</td><td>Work</td><td>10</td><td>Planning & methodology evaluation</td></tr>
<tr><td>71</td><td>19/2</td><td>Blackbox machine</td><td>10</td><td></td></tr>
<tr><td>72</td><td>20/2</td><td>Whitebox machine 1</td><td>10</td><td></td></tr>
<tr><td>73 - 77</td><td>21/2 - 25/2</td><td>Work</td><td>0</td><td>Resting after work</td></tr>
<tr><td>78 - 79</td><td>26/2 - 27/2</td><td>Whitebox machine 2</td><td>20</td><td></td></tr>
<tr><td>80 - 84</td><td>28/2 - 4/3</td><td>Work</td><td>10</td><td>Figuring out Remote debugging</td></tr>
<tr><td>85 - 86</td><td>5/3 - 6/3</td><td>Extra vulns from <a href="https://forums.offensive-security.com/showthread.php?32421-Extra-Extra-Miles">forum post</a></td><td>20</td><td></td></tr>
<tr><td>87 - 91</td><td>7/3 - 11/3</td><td>Work</td><td>10</td><td>Reviewing notes</td></tr>
</table>

Between the 11/12 and the 6/1, I was finishing almost one chapter per day except for the holidays. I then spent a day partly resting and planning when to do what. This planning took some time since I was reading all the extra miles and assigning them a difficulty rating of Easy, Medium or Hard depending on how difficult it would be for someone with my background to finish them. This helped me know what I should expect. After the planning, I spent a total of approximately 269 hours, between the 8/1 and 13/2, finishing all the extra miles. This number of hours is slightly inflated since I would sometimes tweak the extra miles exercises a little bit to see if I could manage to do them under different constraints.

Once I had finished the extra miles, I focused on the three extra machines that were barely metioned in the course material. These were 1 machine where I did not have source code access and 2 where I did have source code access. Thereafter, I spent some time trying to figure out exactly how to perform remote debugging in the different languages which were incldued in the course, as this was something that was not always completely clear to me when encountering large code bases. Then, I spent some time finding additional vulnerabilites that were not mentioned in the course material, but that students had mentioned in [the forums](https://forums.offensive-security.com/showthread.php?32421-Extra-Extra-Miles). Finally, the last couple of days, I reviewed my notes to ensure that I had not missed anything.

<img src="/assets/{{ imgDir }}/desk.jpg" width="60%" />

Once my lab access ended, I made sure to prepare a template for the exam report according to the [exam guide](https://help.offensive-security.com/hc/en-us/articles/360046869951-OSWE-Exam-Guide). In addition, I prepared a camera for the proctoring by mounting it on a tripod since the proctorers needed to half of my body, as demonstrated in the picture above. Additionally, I bought a lot of snacks, as can be seen in the image below. I also prepared two extra sets of earphones, my passport and a pair of earplugs to have these easily available.

<img src="/assets/{{ imgDir }}/snacks.jpg" width="60%" />

Finally, I attempted the 48 hour exam (+24 hours for sending in the report) for the first time on Saturday 25/3 at 9 AM. I chose 9 AM since that was the time I would usually start working, hoping that my brain would feel like the exam was just regular lab work. I felt a bit nervous before doing the exam as I knew that I wasn't going to sleep much and expected to feel quite frustrated. However, thanks to all the preparation I had been doing, the exam was slightly easier than I expected and a lot of fun! After almost 70 hours with only 6 hours of sleep, I handed in my 58 pages long exam report (At 5:AM). Around 24 hours later, I received an email informing me that I had passed!

<img src="/assets/{{ imgDir }}/pass.png" width="80%" />

Apart from the lack of sleep during the exam, both the lab and the exam was an enjoyable experience. Looking back, I think that I made the right decision in taking the course, since it helped me sharpen my code review skills significantly. Additionally, the course material appeared to be quite well thought through and modern. Consequently, I would recommend anyone who is hesitating on taking this course to just go for it.

# Tips and Checklists
In this section, I provide any tips I would give someone who has yet to do the OSWE. At the end of this section, there is a listing containing these tips divided in a couple of checklists depending on if they are relevant before, during or after lab access. Having the tips in this format makes it easy to turn them into a todo list. 

Before starting the lab access, I recommend familiarizing yourself with the languages which the course is focusing on. As can be seen in the [course syllabus](https://www.offensive-security.com/documentation/awae-syllabus.pdf), this is Java, C#, NodeJS and PHP. Learning how routing works for web applications in these languages is an essential skill for identifying exploitable vulnerabilities. In addition, I would also recommend hacking all of the machines mentioned in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979).

During the course, you will have to script a lot of automated exploits using Python. Since this is a web course, you will need a Python module for sending web requests. As such, I recommend getting familiar with the [requests](https://docs.python-requests.org/en/latest/) module. An example of automated exploitation with Python and this module, can be found [here]({% post_url 2022-04-02-HTB-Holiday-Automated-Exploitation %}). In addition, I strongly recommend getting reasonably good at regular expressions as these can be useful in a large amount of different contexts. An amazing site for playing around with regular expressions is [regex101](https://regex101.com/), as demonstrated below where a regex is used to search for SQLI vulnerabilities.

<img src="/assets/{{ imgDir }}/regex.png" width="80%" />

Once your lab access have started, I recommend taking the approach I ended up taking, which was to read a chapter, watch its corresponding videos and then doing the chapter's exercises. While doing this, you should take a lot of notes. I recommend using [cherrytree](https://www.giuspen.com/cherrytree/) to organize your notes as this makes it really quick to find what you need when you need it. Once you have detailed notes of what you have learned in each chapter, I recommend proceeding with the extra miles exercises. Some of the extra miles exercises will force you to search for vulnerabilities without any guidance, which will force you to establish a methodology for how you approach secure code review. 

After finishing the extra miles exercises, I recommend creating a draft methodology. I did this by making a cherrytree node for all different types of vulnerabilites and what I would search for to find them. Once you are happy with the methodology, you should proceed to apply it to the three extra lab machines, to see if it works in practice. 

If you still have lab access at this point, I recommend trying to find the vulnerabilties which exist in the lab machines but weren't covered in the course material. A list of these can be found [here](https://forums.offensive-security.com/showthread.php?32421-Extra-Extra-Miles). When you have done these, or if your lab time is running out, you should check that you haven't forgotten anything in your notes. Finally, it is good to book an exam slot while you are still practicing in the lab, since exam slots normally need to be scheduled 2 or 3 months in advance.

After your lab access has ended, it is good if you try to dive deeper into subjects where you are still not feeling completely comfortable or where you are still feeling inexperienced. Furthermore, it is mentioned in the [official OSWE exam guide](https://help.offensive-security.com/hc/en-us/articles/360046869951-OSWE-Exam-Guide) that you should hand in a pentest report after your exam. I strongly recommend writing a template for this exam report before the exam starts, as you don't want to loose a bunch of time writing a pentest report from scratch during the exam. There are some good templates available [on github](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown/). 

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
[] There are more vulnerabilites in the lab machines than those mentioned in the exercises and extra miles of the course literature. See if you can find them (See the forums for hints: https://forums.offensive-security.com/showthread.php?32421-Extra-Extra-Miles)
[] Book the exam (Open slots are usually around 2 or 3 months away).
[] Check that nothing is missing from your notes (F.e something you learned during an extra mile e.t.c)

Checklist After Lab Access:
[] Review your notes and dive deeper into subjects where you don't feel super comfortable or experienced
[] Write a template report for the exam
[] Ensure that you have read the exam guide(https://help.offensive-security.com/hc/en-us/articles/360046869951-OSWE-Exam-Guide), have snacks ready, your passport ready and a camera that you can mount appropriately.
[] Make sure to relax before the exam.
{% endhighlight %}


