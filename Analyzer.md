# Snort::Analyzer Code Insight
Analyzer provides the packet acquisition and processing loop. Since it runs in a different thread, it also provides a command facility so that to control the thread and swap configuration.
## Life Cycle
The Analyzer life cycle is managed as a finite state machine. It will start in the NEW state and will transition to the INITIALIZED state once the object is called as part of spinning off a packet thread. Further transitions will be prompted by commands from the main thread. From INITIALIZED, it will go to STARTED via the START command. Similarly, it will go from STARTED to RUNNING via the RUN command. Finally, it will end up in the STOPPED state when the Analyzer object has finished executing. This can be prompted by the STOP command, but may also happen if the Analyzer finishes its operation for other reasons (such as encountering an error condition). The one other state an Analyzer may be in is PAUSED, which will occur when it receives the PAUSE command while in the RUNNING state. A subsequent RESUME command will switch it back from PAUSED to RUNNING. One of the primary drivers of this state machine pattern is to allow the main thread to have synchronization points with the packet threads such that it can drop privileges at the correct time (based on the limitations of the selected DAQ module) prior to starting packet processing.

Two other commands are currently available: SWAP and ROTATE. The SWAP command will swap in a new configuration at the earliest convenience, and the ROTATE command will cause open per-thread output files to be closed, rotated, and reopened anew.
## Definition
The definition of Analyzer is listed as follows:
```C++
class Analyzer
{
public:
    enum class State {
        NEW,
        INITIALIZED,
        STARTED,
        RUNNING,
        PAUSED,
        STOPPED,
        NUM_STATES
    };

    static Analyzer* get_local_analyzer();
    static ContextSwitcher* get_switcher();
    static void set_main_hook(MainHook_f);

    Analyzer(snort::SFDAQInstance*, unsigned id, const char* source, uint64_t msg_cnt = 0);
    ~Analyzer();

    void operator()(Swapper*, uint16_t run_num);

    State get_state() { return state; }
    const char* get_state_string();
    const char* get_source() { return source.c_str(); }

    void set_pause_after_cnt(uint64_t msg_cnt) { pause_after_cnt = msg_cnt; }
    void set_skip_cnt(uint64_t msg_cnt) { skip_cnt = msg_cnt; }

    void execute(snort::AnalyzerCommand*);

    void post_process_packet(snort::Packet*);
    bool process_rebuilt_packet(snort::Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, uint32_t pktlen);
    bool inspect_rebuilt(snort::Packet*);
    void finalize_daq_message(DAQ_Msg_h, DAQ_Verdict);
    void add_to_retry_queue(DAQ_Msg_h);

    // Functions called by analyzer commands
    void start();
    void run(bool paused = false);
    void stop();
    void pause();
    void resume(uint64_t msg_cnt);
    void reload_daq();
    void reinit(const snort::SnortConfig*);
    void stop_removed(const snort::SnortConfig*);
    void rotate();
    snort::SFDAQInstance* get_daq_instance() { return daq_instance; }

    bool is_idling() const
    { return idling; }

private:
    void analyze();
    bool handle_command();
    void handle_commands();
    void handle_uncompleted_commands();
    DAQ_RecvStatus process_messages();
    void process_daq_msg(DAQ_Msg_h, bool retry);
    void process_daq_pkt_msg(DAQ_Msg_h, bool retry);
    void post_process_daq_pkt_msg(snort::Packet*);
    void process_retry_queue();
    void set_state(State);
    void idle();
    bool init_privileged();
    void init_unprivileged();
    void term();
    void show_source();
    void add_command_to_uncompleted_queue(snort::AnalyzerCommand*, void*);
    void add_command_to_completed_queue(snort::AnalyzerCommand*);

public:
    std::queue<snort::AnalyzerCommand*> completed_work_queue;
    std::mutex completed_work_queue_mutex;
    std::queue<snort::AnalyzerCommand*> pending_work_queue;

private:
    std::atomic<State> state;
    unsigned id;
    bool exit_requested = false;
    bool idling = false;
    uint64_t exit_after_cnt;
    uint64_t pause_after_cnt = 0;
    uint64_t skip_cnt = 0;
    std::string source;
    snort::SFDAQInstance* daq_instance;
    RetryQueue* retry_queue = nullptr;
    OopsHandler* oops_handler = nullptr;
    ContextSwitcher* switcher = nullptr;
    std::mutex pending_work_queue_mutex;
    std::list<UncompletedAnalyzerCommand*> uncompleted_work_queue;
};
```
The enumerate State define 6 states illustrated in the first paragraph of this article. The following three functions are some utils for other callers. Note that `set_main_hook` sets the main_hook function pointer as a `MainHook_f` function for the following pre-processing(package rebuild) operations.

The constructor of Analyzer takes 4 parameters, a pointer of snort::SFDAQInstance (a Data AcQuisition Instance), an identifier, the source of the data (pcap, etc.) and the count of the total message.

```C++
void post_process_packet(snort::Packet*);
bool process_rebuilt_packet(snort::Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, uint32_t pktlen);
bool inspect_rebuilt(snort::Packet*);
void finalize_daq_message(DAQ_Msg_h, DAQ_Verdict);
void add_to_retry_queue(DAQ_Msg_h);
```
Above methods are used to handle package processing. And methods that are below them are called by analyzer commands.