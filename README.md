# basic_com
**volume warning high volume**

## Getting Started

**Make sure Docker Desktop is installed and running as administrator.**

   * If you don't have it, download and install Docker Desktop from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop) 
   * Make sure you've enabled the WSL 2 backend option in Docker Desktop settings.

**Download the Game Files:**

   * Get the game files from the repository. 

## Running the Game (Windows)

**On the Main Computer (Where the Load Balancer Runs):**

1. **Open an Elevated Command Prompt:**
   * Right-click on the Start menu (Windows icon) and choose "Command Prompt (Admin)." 

2. **Navigate to the Game Folder:** 
   * In the command prompt, type `cd` followed by the path to the folder where you downloaded the game files (e.g., `cd C:\Users\YourName\Downloads\CyberOffensive`). Press Enter.

3. **Start the Load Balancer:**
   * Type `run-load-balancer.bat` and press Enter. This will start the Load Balancer.

**On Five Computers (Including the Main Computer):**

1. **Open an Elevated Command Prompt:**
   * Right-click on the Start menu (Windows icon) and choose "Command Prompt (Admin)." 

2. **Navigate to the Game Folder:** 
   * In the command prompt, type `cd` followed by the path to the folder where you downloaded the game files (e.g., `cd C:\Users\YourName\Downloads\CyberOffensive`). Press Enter.

3. **Start the Sub-Servers:**
   * Type `run-sub-server.bat` and press Enter. This will start the sub-servers. 

**Install the Game:**

* Navigate to the folder where you downloaded the game files (e.g., `cd C:\Users\YourName\Downloads\CyberOffensive`) 
* Run the `*.msi` file (usually by double-clicking it) to install the game.

**Start the Game:**

*  An executable (`.exe`) file for the game should be on your desktop. Double-click it to start the game.

**Enjoy!**

**Important Notes:**
* **Installation Folder:** Do not change the path shown in the msi otherwise the game won't run
* **Docker Desktop:** Make sure Docker Desktop is running in the background on *all* computers while the game is active.
* **Administrator Mode:** You'll always need to open the Command Prompt as an administrator (using "Command Prompt (Admin)") to run the batch files. 
* **Network Issues:**  If the game doesn't load, it might be because of a network problem. Make sure your internet connection is working and that all computers are connected to the same network.
