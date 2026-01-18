# Cisco Switch Initial Configuration Guide

## Training Resource
- **Good video on how to program a Cisco switch:**  
  https://youtu.be/IJWFwFL5Vzw

---

## Step 1: Connect to the Switch with PuTTY (Serial)
- Connect using **PuTTY** with a **Serial** connection.
- To determine the correct COM port:
  - Open **Device Manager** on Windows.
  - Look under **Ports (COM & LPT)**.
  - Identify the entry similar to: `USB Serial Port (COM#)`.
  - Use this COM number when selecting **Serial** in PuTTY.

---

## Step 2: Start the Terminal Session
- After connecting, press **Enter** in the PuTTY terminal to display the prompt.
- When prompted to enter **initial configuration mode**, select **no**.

---

## Step 3: Enter Privileged EXEC Mode
```text
> en
```

---

## Step 4: Enter Global Configuration Mode
```text
# conf t
```

---

## Step 5: Paste the Configuration
- Paste the configuration **section by section**.
- Do **not** paste more than **~50 lines at a time**.
  - Pasting the entire file at once can overload the buffer and cause commands to fail.
- Update the **<ClearTextPassword>** every place is appears in the txt file your using
- The **enable secret** and **VTY password** **must match** for compatibility with **Cheesy Arena**.

```text
# <Paste in the file>
```

---

## Step 6: Exit Configuration Mode
```text
# end
```

---

## Step 7: Verify the Running Configuration
```text
# show running-configuration
```

- Note the updated **enable secret 5** value.
- This value is an **MD5 hash** and is difficult to decrypt.
- Update your configuration file and store it in your repository.

---

## Step 8: Save the Configuration
```text
# copy running-config start-config
```

---

## Step 9: Exit the Switch Session
```text
# exit
```

# Switch Updates / Maintenance
## Update the switch config
Once the switch has been initially configured you can update the batch using the following command from a linux prompt.  
All instances of \<ClearTextPassword\> in the config file will be replaced with the value supplied as \<new_pass\>

```text
./deploy_config.sh <config_file> <ip> '<current_pass>' '<new_pass>'
```

Note: You may need to run 'chmod +x *.sh' to make the shell scripts executable when initially pulled from GitHub

## Backup Config
If you want a copy of the current running configuraiton you can use the following command

```text
./backup_config.sh <switch_ip> <password>
```