# Snort::Pig Code Insight
Snort::Pig is the core class of Snort, in detail, every Packet thread is corresponding with an instance of Pig class, with the ability to be bound with a data source and handle its incoming packets (decode, pre-process, detect and do some actions). The definition of Pig class is listed as follows:
```C++
class Pig
{
public:
    Pig() = default;

    void set_index(unsigned index) { idx = index; }

    bool prep(const char* source);
    void start();
    void stop();

    bool queue_command(AnalyzerCommand*, bool orphan = false);
    void reap_commands();

    Analyzer* analyzer = nullptr;
    bool awaiting_privilege_change = false;
    bool requires_privileged_start = true;

private:
    void reap_command(AnalyzerCommand* ac);

    std::thread* athread = nullptr;
    unsigned idx = (unsigned)-1;
};
```