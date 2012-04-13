#include "rtp.h"

int main(int argc, char** argv)
{
    rtp_s input;
    char ip[40] = "235.0.1.192";
    rtp_init(&input, ip, 57356);

    while (1)
    {
        sleep(10);
    }
    return 0;
}
