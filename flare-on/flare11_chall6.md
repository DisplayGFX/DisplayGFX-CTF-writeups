Flare-On 11 <br>By DisplayGFX <br>Challenge 6: bloke2 
===

 Challenge Description:
```
You've been so helpful lately, and that was very good work you did. Yes, I'm going to put it right here, on the refrigerator, very good job indeed. You're the perfect person to help me with another issue that come up. One of our lab researchers has mysteriously disappeared. He was working on the prototype for a hashing IP block that worked very much like, but not identically to, the common Blake2 hash family. Last we heard from him, he was working on the testbenches for the unit. One of his labmates swears she knew of a secret message that could be extracted with the testbenches, but she couldn't quite recall how to trigger it. Maybe you could help?
```

This one seemed hard... until I used the most recent chatgpt model `o1`.

This solved the challenge in seconds, rather than minutes. My head was spinning once I switched tabs back, and saw the solution. Might as well give the ~~link~~ message summary (apparently links expire???) rather than take credit myself.

```
[dump the contents of the files provided]
Certainly! Let's dive deeper into this challenge and work step by step to uncover the secret message hidden within the Verilog code. Below is a detailed guide tailored to help you solve this CTF.
Step 1: Understand the Code Structure

You've been provided with several Verilog modules and testbenches:

    bloke2b_tb.v and bloke2s_tb.v: Testbenches for the Bloke2b and Bloke2s hash functions.

    bloke2b.v and bloke2s.v: Top-level modules for the Bloke2b and Bloke2s hash functions.

    bloke2.v: Core module implementing the Bloke2 hash algorithm.

    Supporting modules: data_mgr, f_unit, g_unit, g_over_2, f_sched, and f_sched_tb.

Your goal is to extract a secret message embedded within the testbenches or the modules by triggering specific conditions.
Step 2: Analyze the Testbenches

Let's focus on the testbenches, specifically bloke2b_tb.v:

initial begin
    // Initialize our start and finish lines.
    start <= 1'b0;
    finish <= 1'b0;

    // Kick off the clock, since it needs an event to start.
    clk <= 1'b1;

    // Wait for the next clock edge and pull the reset.
    @(posedge clk);
    rst <= 1'b0;

    // Run a few tests.
    hash_message("");
    hash_message("123");
    hash_message("abc");

    // And we're done, stop the clock.
    done <= 1'b1;
end

The hash_message task runs several test strings through the hashing function.
Step 3: Examine the hash_message Task

task hash_message (
    input [1023:0] msg
);
    integer i, len;
begin
    // Get the string length
    for (i = 0; msg[8*i +: 8] != 0; i++); len = i;

    // Set our start and finish lines correctly.
    start <= 1'b1;
    finish <= 1'b0;
    @(posedge clk);
    start <= 1'b0;
    finish <= 1'b0;

    // Wait until it signals readiness.
    while (!din_ready) @(posedge clk);

    // Write it in byte by byte when din_ready is asserted.
    for (i = len - 1; i >= 0; i--) begin
        din <= msg[8*i +: 8];
        din_valid <= 1'b1;
        do @(posedge clk); while (!din_ready);
    end

    // Deassert data valid, since we're done.
    din_valid <= 1'b0;

    // And assert finish for a clock.
    finish <= 1'b1;
    @(posedge clk);
    finish <= 1'b0;

    // Wait until the message processes.
    @(negedge dout_end);
end endtask

Key observations:

    The start signal is asserted before sending the data.

    The finish signal is asserted after all data has been sent.

Step 4: Investigate the Secret Condition

Looking into the data_mgr module, we find this crucial piece of code:

always @(posedge clk) begin
    if (rst | start) begin
        // ...
        tst <= finish;
    end else begin
        // ...
    end
end

    The tst register is assigned the value of finish when start is asserted.

    This suggests that if both start and finish are asserted simultaneously, tst will be set to 1.

Later in the data_mgr module:

if (h_rdy) begin
    out_cnt <= W;
    h <= h_in ^ (TEST_VAL & {(W*16){tst}});
end

    When tst is 1, the output hash h is XORed with TEST_VAL.

    This means a special output is produced when both start and finish are asserted together.

Step 5: Modify the Testbench to Trigger the Secret Message

Modify the hash_message task in your testbench to assert both start and finish simultaneously:
Original Code:

// Set our start and finish lines correctly.
start <= 1'b1;
finish <= 1'b0;
@(posedge clk);
start <= 1'b0;
finish <= 1'b0;

Modified Code:

// Set our start and finish lines correctly.
start <= 1'b1;
finish <= 1'b1; // Assert finish along with start
@(posedge clk);
start <= 1'b0;
finish <= 1'b0;
...
```
