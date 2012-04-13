#include "rtp.h"

static void* video_recv_thread(void* arg);
static void* writeThread(void* arg);
static void* writeThread2(void* arg);

static int SetPortReuse(SOCKET sock, int bReuse);
static int JoinGroup(SOCKET sock, const char* strGroupIP);

static frame_t* new_frame(uint8_t* p_frame_data, uint32_t i_size, uint32_t i_type, uint64_t i_stamp);
static int free_frame(frame_t** pp_frame);

static int add_frame(rtp_s* p_rtp, uint8_t* p_frame, uint32_t i_size, uint32_t i_type, uint64_t i_stamp, uint32_t i_flag);
static int clear_frame(rtp_s* p_rtp);
static int dump_frame(uint8_t* p_frame, uint32_t size);

int rtp_init(rtp_s* p_rtp, char* p_ip, int i_port)
{
    int i_ret = 0;
    if (p_rtp == NULL)
    {
        i_ret = -1;
    }
    else
    {
        p_rtp->i_audio_frame_index = 0;
        p_rtp->i_video_frame_index = 0;

        p_rtp->p_video_frame = (uint8_t*) malloc(MAX_VIDEO_FRAME_SIZE);
        p_rtp->p_audio_frame = (uint8_t*) malloc(MAX_AUDIO_FRAME_SIZE);

        p_rtp->i_nalu_ok_flag = 0;
        p_rtp->i_last_pkt_num = 0;
        p_rtp->i_aui_last_pkt_num = 0;

        p_rtp->i_buf_num = 0;
        p_rtp->p_frame_buf = NULL;
        p_rtp->p_frame_header = NULL;

        p_rtp->i_video_time_stamp = 0;
        p_rtp->i_audio_time_stamp = 0;

        p_rtp->i_exit = 0;

        pthread_mutex_init(&p_rtp->mutex, NULL);

        strcpy(p_rtp->p_ip, p_ip);
        p_rtp->i_port = i_port;

        p_rtp->p_opaque = NULL;

        p_rtp->i_video_time = 0;
        p_rtp->i_audio_time = 0;
        p_rtp->i_seq_num = 0;

        threadCreate(video_recv_thread, p_rtp);
        threadCreate(writeThread, p_rtp);
        //threadCreate(writeThread2, p_rtp);
    }

    return i_ret;
}

int rtp_deinit(rtp_s* p_rtp)
{
    int i_ret = 0;

    if (p_rtp != NULL)
    {
        p_rtp->i_exit = 1;
        usleep(1500);

        if (p_rtp->p_video_frame != NULL)
        {
            free(p_rtp->p_video_frame);
            p_rtp->p_video_frame = NULL;
        }

        if (p_rtp->p_audio_frame != NULL)
        {
            free(p_rtp->p_audio_frame);
            p_rtp->p_audio_frame = NULL;
        }
    }
    else
    {
        i_ret = -1;
    }

    return i_ret;
}

static void* video_recv_thread(void* arg)
{
    rtp_s* p_rtp = (rtp_s*) arg;
    SOCKET sock = 0;
    SOCKADDR_IN addr;
    uint8_t p_recv_buf[4096];
    int i_recv_size = 0;
    char p_save_buf[4096];
    int i_time_out = 0;

    if (p_rtp == NULL)
    {
        return NULL;
    }

    while (1)
    {
        if (p_rtp->i_exit == 1)
        {
            break;
        }
        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        addr.sin_family = AF_INET;
        addr.sin_port = htons(p_rtp->i_port);
        if (p_rtp->p_ip[0] != 0)
        {
            addr.sin_addr.s_addr = inet_addr(p_rtp->p_ip);
        }
        else
        {
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
        }

        SetPortReuse(sock, 1);

        // bind
        if (bind(sock, (SOCKADDR*) & addr, sizeof (SOCKADDR_IN)) < 0)
        {
            printf("bind rtp socket error = %s\n", strerror(errno));
            return NULL;
        }

        if (p_rtp->p_ip[0] != 0)
        {
            unsigned int lIP = inet_addr(p_rtp->p_ip);
            if ((lIP & 0x000000E0) == 0xE0)
            {
                if (JoinGroup(sock, p_rtp->p_ip) < 0)
                {
                    printf("JoinGroup failed, group ip = %s\n", p_rtp->p_ip);
                }
                else
                {
                    printf("jion group v4 success, %s\n", p_rtp->p_ip);
                }
            }
        }

        struct timeval t;
        t.tv_sec = 0;
        t.tv_usec = 500000;

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &t, sizeof (t)) == -1)
        {
            printf("set rtp scok recv time out failed %s\n", strerror(errno));
        }

        p_rtp->i_nalu_ok_flag = 0;

        while (1)
        {
            if (p_rtp->i_exit == 1)
            {
                break;
            }

            i_recv_size = recv(sock, p_recv_buf, sizeof (p_recv_buf), 0);
            if (i_recv_size > 0)
            {
                i_time_out = 0;
                rtp_header_t rtp_header;

                get_rtp_header(&rtp_header, p_recv_buf, i_recv_size);
                if (rtp_header.i_pt == 0x60)// VIDEO
                {
                    p_rtp->i_video_time = rtp_header.i_timestamp;
                    int i_size = RtpTo264(p_recv_buf, i_recv_size, p_save_buf, &p_rtp->i_nalu_ok_flag, &p_rtp->i_last_pkt_num);
                    //printf("i_recv_size--2 = %d, i_size = %d, nalu = %d\n", i_recv_size, i_size, p_rtp->i_nalu_ok_flag );

                    if (p_rtp->i_video_time_stamp == 0)
                    {
                        p_rtp->i_video_time_stamp = rtp_header.i_timestamp;

                        p_rtp->i_video_frame_index = 0;
                        memcpy(p_rtp->p_video_frame + p_rtp->i_video_frame_index, p_save_buf, i_size);
                        p_rtp->i_video_frame_index += i_size;

                    }

                    int i_use_data = 0;
                    unsigned char* p_buf = NULL;

                    if (p_rtp->i_video_time_stamp != rtp_header.i_timestamp || p_recv_buf[12] == 0x78)
                    {
                        if (p_rtp->i_video_frame_index > 0)
                        {
                            add_frame(p_rtp, p_rtp->p_video_frame, p_rtp->i_video_frame_index, 1, p_rtp->i_video_time, rtp_header.i_ssrc >> 24);
                        }
                        p_rtp->i_video_frame_index = 0;

                        p_rtp->i_video_time_stamp = rtp_header.i_timestamp;

                        memcpy(p_rtp->p_video_frame + p_rtp->i_video_frame_index, p_save_buf, i_size);
                        p_rtp->i_video_frame_index += i_size;
                    }
                    else
                    {
                        memcpy(p_rtp->p_video_frame + p_rtp->i_video_frame_index, p_save_buf, i_size);
                        p_rtp->i_video_frame_index += i_size;
                    }
                }
                else if (rtp_header.i_pt == 0x61)//AUDIO
                {
                    p_rtp->i_audio_time = rtp_header.i_timestamp;

                    int i_size = CmmbRtpToAAC(p_recv_buf, i_recv_size, p_save_buf, &p_rtp->i_aui_last_pkt_num);
                    if (p_rtp->i_audio_time_stamp == 0)
                    {
                        p_rtp->i_audio_time_stamp = rtp_header.i_timestamp;
                    }

                    if (p_rtp->i_audio_time_stamp != rtp_header.i_timestamp)
                    {
                        add_frame(p_rtp, p_rtp->p_audio_frame, p_rtp->i_audio_frame_index, 2, rtp_header.i_timestamp, 0);
                        //add_frame(p_rtp, p_recv_buf, i_recv_size, 2, p_rtp->i_audio_time, 0);
                        p_rtp->i_audio_frame_index = 0;

                        p_rtp->i_audio_time_stamp = rtp_header.i_timestamp;
                        memcpy(p_rtp->p_audio_frame + p_rtp->i_audio_frame_index, p_save_buf, i_size);
                        p_rtp->i_audio_frame_index += i_size;
                    }
                    else
                    {
                        memcpy(p_rtp->p_audio_frame + p_rtp->i_audio_frame_index, p_save_buf, i_size);
                        p_rtp->i_audio_frame_index += i_size;
                    }
                }
                else if (rtp_header.i_pt == 0x62)
                {
                }
                else if (rtp_header.i_pt == 0x0E)
                {
                    add_frame(p_rtp, p_recv_buf + 16, i_recv_size-16, 0x4, rtp_header.i_timestamp, 0);
                }
            }
            else
            {
                i_time_out += 500;
                if (i_time_out > 5000)
                {
                    printf("rtp no data recv\n");
                    i_time_out = 0;
                }
            }
        }

        close(sock);
        sock = -1;
    }

    close(sock);
    sock = -1;
    return NULL;
}

int get_rtp_header(rtp_header_t* p_header, uint8_t* p_buf, uint32_t i_size)
{
    int i_ret = 0;

    if (p_header == NULL || p_buf == NULL || i_size < 0)
    {
        i_ret = -1;
    }
    else
    {
        p_header->i_version = (p_buf[0] & 0xC0) >> 6;
        p_header->i_extend = (p_buf[0] & 0x10) >> 4;
        p_header->i_cc = (p_buf[0] & 0x0F);
        p_header->i_m_tag = (p_buf[1] & 0x80) >> 7;
        p_header->i_pt = (p_buf[1] & 0x7F);
        p_header->i_seq_num = (p_buf[2] << 8);
        p_header->i_seq_num += p_buf[3];
        p_header->i_timestamp = (p_buf[4] << 24);
        p_header->i_timestamp += (p_buf[5] << 16);
        p_header->i_timestamp += (p_buf[6] << 8);
        p_header->i_timestamp += p_buf[7];

        p_header->i_ssrc = (p_buf[8] << 24);
        p_header->i_ssrc += (p_buf[9] << 16);
        p_header->i_ssrc += (p_buf[10] << 8);
        p_header->i_ssrc += p_buf[11];

        //p_header->i_csrc = (p_buf[12] << 24);
        //p_header->i_csrc += (p_buf[13] << 16);
        //p_header->i_csrc += (p_buf[14] << 8);
        //p_header->i_csrc += p_buf[15];

        i_ret = 12;
        return i_ret;
    }
    return i_ret;
}

//buffer:接收到的数据；recv_bytes数据长度
//int RtpTo264(unsigned char* buffer, int recv_bytes, unsigned char* save_buffer, int* pnNALUOkFlag, int* pnLastPkt)

int RtpTo264(unsigned char* buffer, int recv_bytes, char* save_buffer, uint32_t* pnNALUOkFlag, uint32_t* pnLastPkt)
{
    unsigned int FU_FLAG = 0;
    unsigned int MARK_BIT = 0;
    unsigned char NAL_HEAD = 0;
    int save_len = 0;
    unsigned int nPkt = 0;
    nPkt = (unsigned int) (((buffer[2]) << 8) | (buffer[3]));

    if (recv_bytes < 13)
    {
        return -1;
    }

    if (nPkt - (*pnLastPkt) > 1)
    {
        //printf("rtp lose packet, nPkt = %u, last = %u\n", nPkt, *pnLastPkt);//掉包。
        *pnNALUOkFlag = 0;
    }
    if (nPkt < (*pnLastPkt))
    {
        //跳变
        //printf("rtp lose packet 2\n");
    }
    (*pnLastPkt) = nPkt;
    FU_FLAG = (buffer[12])&(0x1C); //第13个字节和0x1C相与

    //printf("%x %x %x %x %x %x\n", buffer[12], buffer[13], buffer[14],buffer[15],buffer[16],buffer[17]);
    if (0x1C == FU_FLAG)//如果是FU型分割
    {
        //printf("FU_FLAG\n");
        MARK_BIT = (buffer[1]) >> 7; //取第二个字节的最高位，以便判断是否是此NALU的最后一包
        if ((*pnNALUOkFlag) == 0)//这是当前NALU的第一包
        {
            if ((recv_bytes - 14) <= 0)
            {
            }
            else
            {
                NAL_HEAD = ((buffer[12])&(0xE0)) | ((buffer[13])&(0x1F)); //取第13个字节的高3位和第14字节的低5位，拼成此NALU的头
                memset(save_buffer, 0, sizeof (save_buffer));
                save_buffer[3] = 1;
                save_buffer[4] = NAL_HEAD; //将NALU的头保存起来

                memcpy(&(save_buffer[5]), &(buffer[14]), recv_bytes - 14); //从第15字节开始就是NALU的数据部分，保存起来
                save_len = recv_bytes - 9; //减12字节的RTP头，减2字节FU头，加4字节的起始码，加1字节的NALU头
                *pnNALUOkFlag = 1; //这是当前NALU的第一包，接下来的就不是第一包了。
                /*
                NAL_HEAD=((buffer[12])&(0xE0))|((buffer[13])&(0x1F));//取第13个字节的高3位和第14字节的低5位，拼成此NALU的头
                memset(save_buffer,0,sizeof(save_buffer));
                save_buffer[2]=1;
                save_buffer[3]=NAL_HEAD;//将NALU的头保存起来

                memcpy(&(save_buffer[4]),&(buffer[14]),recv_bytes-14);//从第15字节开始就是NALU的数据部分，保存起来
                save_len=recv_bytes-10;//减12字节的RTP头，减2字节FU头，加3字节的起始码，加1字节的NALU头
                pnNALUOkFlag=1;//这是当前NALU的第一包，接下来的就不是第一包了。
                 */
            }
        }
        else
        {
            memset(save_buffer, 0, sizeof (save_buffer));
            if ((recv_bytes - 14) > 4096)
            {
            }
            else if ((recv_bytes - 14) <= 0)
            {
            }
            else
            {
                memcpy(save_buffer, buffer + 14, recv_bytes - 14); //不是NALU的第一包，直接从第15字节保存起来
                save_len = recv_bytes - 14; //减12字节的RTP头，减2字节FU头
            }
        }
        if (MARK_BIT == 1)//这是此NALU的最后一包
        {
            *pnNALUOkFlag = 0; //这一NALU已经收齐，下面再来的包就是下一个NALU的了
        }
    }
    else if (FU_FLAG == 0x18) // 多个NALU包，组合封包
    {
        //printf("recv_bytes = %d\n", recv_bytes);
        memset(save_buffer, 0, sizeof (save_buffer));
        int i_index = 0;
        int i_src_index = 13;
        short i_len = 0;
        while (1)
        {
            if ((i_src_index) >= recv_bytes)
            {
                break;
            }
            save_buffer[i_index + 0] = 0;
            save_buffer[i_index + 1] = 0;
            save_buffer[i_index + 2] = 0;
            save_buffer[i_index + 3] = 1;
            i_index += 4;
            i_len = (buffer[i_src_index] << 8);
            i_src_index += 1;
            i_len += buffer[i_src_index];
            if ((i_len >= recv_bytes) || (i_len < 0))
            {
                i_index = 0;
                break;
            }

            //printf("i_index = %d, i_len = %d\n", i_index, i_len);
            i_src_index += 1;
            memcpy(save_buffer + i_index, buffer + i_src_index, i_len);
            i_src_index += i_len;
            i_index += i_len;
            /*
            save_buffer[i_index+0] = 0;
            save_buffer[i_index+1] = 0;
            save_buffer[i_index+2] = 1;

            i_index += 3;
            i_len = (buffer[i_src_index] << 8);
            i_src_index += 1;
            i_len += buffer[i_src_index];
            //printf("i_index = %d, i_len = %d\n", i_index, i_len);
            i_src_index += 1;
            memcpy(save_buffer+i_index, buffer+i_src_index, i_len);
            i_src_index += i_len;
            i_index += i_len;
             */
        }
        save_len = i_index;
        //printf("save_len = %d\n", save_len);
    }
    else if (FU_FLAG == 0x19)
    {
        // TODO
        printf("unkown rtp packet, todo\n");
    }
    else //不是FU型分割，即一个NALU就是一包
    {
        memset(save_buffer, 0, sizeof (save_buffer));
        save_buffer[3] = 1;
        memcpy(&(save_buffer[4]), &(buffer[12]), recv_bytes - 12); //第13字节是此NALU的头，14字节及以后是NALU的内容，一起保存
        save_len = recv_bytes - 12 + 4; //减12字节的RTP头
        *pnNALUOkFlag = 0; //一个NALU就是一包，下面再来的包就是下一个NALU的了
        /*
        memset(save_buffer,0,sizeof(save_buffer));
        save_buffer[2]=1;
        memcpy(&(save_buffer[3]),&(buffer[12]),recv_bytes-12);//第13字节是此NALU的头，14字节及以后是NALU的内容，一起保存
        save_len=recv_bytes-12+3;//减12字节的RTP头
         *pnNALUOkFlag=0; //一个NALU就是一包，下面再来的包就是下一个NALU的了
         */
    }

    return save_len; //save_buffer里面要保存多少字节的数据
}

//buffer:接收到的数据；recv_bytes数据长度
//int CmmbRtpToAAC(unsigned char *buffer, int recv_bytes, unsigned char* save_buffer, int* pnLastPkt)

int CmmbRtpToAAC(unsigned char *buffer, int recv_bytes, char* save_buffer, uint32_t* pnLastPkt)
{
    int save_len = 0; // 7 bytes adts head
    unsigned int nPkt = 0;
    nPkt = (unsigned int) (((buffer[2]) << 8) | (buffer[3]));

    if (nPkt - (*pnLastPkt) > 1)
    {
        //printf("lose nPkt = %u, last = %u\n", nPkt, *pnLastPkt);//掉包。
    }
    if (nPkt<*(pnLastPkt))
    {
        //跳变
    }
    (*pnLastPkt) = nPkt;

#if 1
    // 解码
    if (buffer[12] == 0xff)
    {
        //printf("AAC1 --------------\n");
        memcpy(&(save_buffer[7]), &(buffer[14]), recv_bytes - 14);
        save_len += (recv_bytes - 14);
    }
    else
    {
        //printf("AAC2 --------------\n");
        memcpy(&(save_buffer[7]), &(buffer[13]), recv_bytes - 13);
        save_len += (recv_bytes - 13);
    }
    save_len += 7;
    save_buffer[0] = (char) 0xff;
    save_buffer[1] = (char) 0xf9;
    save_buffer[2] = (0x01 << 6) | (0x06 << 2) | 0x00; //0x06  means  24000Hz  ; 0x03  means 48000Hz can not play
    save_buffer[3] = (char) 0x80; //双声道？ a=rtpmap:97 mpeg4-generic/44100/2
    //单声道？(char)0x40;    a=rtpmap:97 mpeg4-generic/44800
    save_buffer[4] = (save_len >> 3)&0xff;
    save_buffer[5] = ((save_len & 0x07) << 5 | 0x1f);
    save_buffer[6] = (char) 0xfc;
#endif

#if 0
    // 实时流
    if (buffer[12] == 0xff)
    {
        //printf("AAC1 --------------\n");
        memcpy(&(save_buffer[0]), &(buffer[13]), recv_bytes - 13);
        save_len += (recv_bytes - 13);
    }
    else
    {
        //printf("AAC2 --------------\n");
        memcpy(&(save_buffer[0]), &(buffer[12]), recv_bytes - 12);
        save_len += (recv_bytes - 12);
    }
#endif
    //printf("AAC  %x, %x, %x\n", save_buffer[0], save_buffer[1], save_buffer[2]);
    //save_buffer[0] = (char)0xff;
    //save_buffer[1] = (char)0xf9;
    //save_buffer[2] = (0x01<<6)|(0x06<<2)|0x00; //0x06  means  24000Hz  ; 0x03  means 48000Hz can not play
    //save_buffer[3] = (char)0x80;  //双声道？ a=rtpmap:97 mpeg4-generic/44100/2
    //															//单声道？(char)0x40;    a=rtpmap:97 mpeg4-generic/44800
    //save_buffer[4] = (save_len>>3)&0xff;
    //save_buffer[5] = ((save_len&0x07)<<5|0x1f);
    //save_buffer[6] = (char)0xfc;
    return save_len;
}


//int  CmmbRtpToAAC (unsigned char *buffer,int recv_bytes,unsigned char* save_buffer,  int* pnLastPkt )//buffer:接收到的数据；recv_bytes数据长度
//{
//	int save_len=7;// 7 bytes adts head
//	unsigned int nPkt=0;
//	nPkt=(unsigned  int)(((buffer[2])<<8)|(buffer[3]));
//
//	if(nPkt-(*pnLastPkt)>1)
//	{
//		printf("lose \n");//掉包。
//	}
//	if(nPkt<*(pnLastPkt))
//	{
//		//跳变
//	}
//	(*pnLastPkt)=nPkt;
//	if(buffer[12]==0xff)
//	{
//		memcpy(&(save_buffer[7]),&(buffer[14]),recv_bytes-14);
//		save_len+=(recv_bytes-14);
//	}
//	else
//	{
//		memcpy(&(save_buffer[7]),&(buffer[13]),recv_bytes-13);
//		save_len+=(recv_bytes-13);
//	}
//
//	save_buffer[0] = (char)0xff;
//	save_buffer[1] = (char)0xf9;
//	save_buffer[2] = (0x01<<6)|(0x06<<2)|0x00; //0x06  means  24000Hz  ; 0x03  means 48000Hz can not play
//	save_buffer[3] = (char)0x80;  //双声道？ a=rtpmap:97 mpeg4-generic/44100/2
//																//单声道？(char)0x40;    a=rtpmap:97 mpeg4-generic/44800
//	save_buffer[4] = (save_len>>3)&0xff;
//	save_buffer[5] = ((save_len&0x07)<<5|0x1f);
//	save_buffer[6] = (char)0xfc;
//	return save_len;
//}
//

int get_rtp_aac_packet(unsigned char* p_data, int i_size, unsigned char* p_rtp_data, rtp_header_t* p_header)
{
    int i_ret = 0;
    int i_mark_bit = 1;

    p_rtp_data[0] = 0x80;
    p_rtp_data[1] = (i_mark_bit << 7) + 0x61;
    p_rtp_data[2] = (unsigned char) ((p_header->i_seq_num) >> 8);
    p_rtp_data[3] = (unsigned char) ((p_header->i_seq_num));
    p_rtp_data[4] = (unsigned char) (p_header->i_timestamp >> 24);
    p_rtp_data[5] = (unsigned char) (p_header->i_timestamp >> 16);
    p_rtp_data[6] = (unsigned char) (p_header->i_timestamp >> 8);
    p_rtp_data[7] = (unsigned char) (p_header->i_timestamp);

    p_rtp_data[8] = (unsigned char) ((p_header->i_ssrc) >> 24);
    p_rtp_data[9] = (unsigned char) ((p_header->i_ssrc) >> 16);
    p_rtp_data[10] = (unsigned char) ((p_header->i_ssrc) >> 8);
    p_rtp_data[11] = (unsigned char) ((p_header->i_ssrc));

    //printf("%d, %x, %x, i_size = %d\n", p_data[0], p_data[1], p_data[2], i_size);
    memcpy(p_rtp_data + 12, p_data, i_size);
    i_ret = 12 + i_size;

    return i_ret;
}

int get_rtp_video_paket(unsigned char* p_data, int i_size, unsigned char* p_rtp_data, rtp_header_t* p_header, int i_nalu_flag)
{
    int i_ret = 0;
    int i_mark_bit = 0;
    unsigned char i_nalu_header = p_header->i_nalu_header;

    // 头12个字节为rtp包的包头, just for h264
    p_rtp_data[0] = 0x80;
    p_rtp_data[1] = (i_mark_bit << 7) + 0x60;
    p_rtp_data[2] = (unsigned char) ((p_header->i_seq_num) >> 8);
    p_rtp_data[3] = (unsigned char) ((p_header->i_seq_num));
    p_rtp_data[4] = (unsigned char) (p_header->i_timestamp >> 24);
    p_rtp_data[5] = (unsigned char) (p_header->i_timestamp >> 16);
    p_rtp_data[6] = (unsigned char) (p_header->i_timestamp >> 8);
    p_rtp_data[7] = (unsigned char) (p_header->i_timestamp);

    p_rtp_data[8] = (unsigned char) ((p_header->i_ssrc) >> 24);
    p_rtp_data[9] = (unsigned char) ((p_header->i_ssrc) >> 16);
    p_rtp_data[10] = (unsigned char) ((p_header->i_ssrc) >> 8);
    p_rtp_data[11] = (unsigned char) ((p_header->i_ssrc));

    //printf("i_seq_num = %d, i_timestamp = %d\n", p_header->i_seq_num, p_header->i_timestamp);

    if (i_nalu_flag == 3)
    {
        memcpy(p_rtp_data + 12, p_data, i_size);
        i_ret = i_size + 12;
    }
    else if (i_nalu_flag == 0)
    {
        i_mark_bit = 0;
        p_rtp_data[1] = (i_mark_bit << 7) + 0x60;
        unsigned char i_ser_bits = 0x04;
        p_rtp_data[12] = (i_nalu_header & 0xE0) + 0x1C;
        p_rtp_data[13] = (i_ser_bits << 5) + (i_nalu_header & 0x1F);

        memcpy(p_rtp_data + 14, p_data + 1, i_size - 1);
        i_ret = i_size - 1 + 14;
    }
    else if (i_nalu_flag == 1)
    {
        i_mark_bit = 0;
        p_rtp_data[1] = (i_mark_bit << 7) + 0x60;
        unsigned char i_ser_bits = 0x00;
        p_rtp_data[12] = (i_nalu_header & 0xE0) + 0x1C;
        p_rtp_data[13] = (i_ser_bits << 5) + (i_nalu_header & 0x1F);

        memcpy(p_rtp_data + 14, p_data, i_size);
        i_ret = i_size + 14;
    }
    else if (i_nalu_flag == 2)
    {
        i_mark_bit = 1;
        p_rtp_data[1] = (i_mark_bit << 7) + 0x60;
        unsigned char i_ser_bits = 0x02;
        p_rtp_data[12] = (i_nalu_header & 0xE0) + 0x1C;
        p_rtp_data[13] = (i_ser_bits << 5) + (i_nalu_header & 0x1F);

        memcpy(p_rtp_data + 14, p_data, i_size);
        i_ret = i_size + 14;
    }
    return i_ret;
}

int get_rtp_pcma_packet(unsigned char* p_data, int i_size, unsigned char* p_rtp_data, rtp_header_t* p_header)
{
    int i_ret = 0;
    int i_mark_bit = 1;

    p_rtp_data[0] = 0x80;
    p_rtp_data[1] = (i_mark_bit << 7) + 8;
    p_rtp_data[2] = (unsigned char) ((p_header->i_seq_num) >> 8);
    p_rtp_data[3] = (unsigned char) ((p_header->i_seq_num));
    p_rtp_data[4] = (unsigned char) (p_header->i_timestamp >> 24);
    p_rtp_data[5] = (unsigned char) (p_header->i_timestamp >> 16);
    p_rtp_data[6] = (unsigned char) (p_header->i_timestamp >> 8);
    p_rtp_data[7] = (unsigned char) (p_header->i_timestamp);

    p_rtp_data[8] = (unsigned char) ((p_header->i_ssrc) >> 24);
    p_rtp_data[9] = (unsigned char) ((p_header->i_ssrc) >> 16);
    p_rtp_data[10] = (unsigned char) ((p_header->i_ssrc) >> 8);
    p_rtp_data[11] = (unsigned char) ((p_header->i_ssrc));

    memcpy(p_rtp_data + 12, p_data, i_size);
    i_ret = (i_size + 12);

    return i_ret;
}

int get_rtp_audio_paket(unsigned char* p_data, int i_size, unsigned char* p_rtp_data, rtp_header_t* p_header)
{
    int i_ret = 0;
    int i_mark_bit = 1;

    p_rtp_data[0] = 0x80;
    p_rtp_data[1] = (i_mark_bit << 7) + 0x0E;
    p_rtp_data[2] = (unsigned char) ((p_header->i_seq_num) >> 8);
    p_rtp_data[3] = (unsigned char) ((p_header->i_seq_num));
    p_rtp_data[4] = (unsigned char) (p_header->i_timestamp >> 24);
    p_rtp_data[5] = (unsigned char) (p_header->i_timestamp >> 16);
    p_rtp_data[6] = (unsigned char) (p_header->i_timestamp >> 8);
    p_rtp_data[7] = (unsigned char) (p_header->i_timestamp);

    p_rtp_data[8] = (unsigned char) ((p_header->i_ssrc) >> 24);
    p_rtp_data[9] = (unsigned char) ((p_header->i_ssrc) >> 16);
    p_rtp_data[10] = (unsigned char) ((p_header->i_ssrc) >> 8);
    p_rtp_data[11] = (unsigned char) ((p_header->i_ssrc));

    p_rtp_data[12] = 0;
    p_rtp_data[13] = 0;
    p_rtp_data[14] = 0;
    p_rtp_data[15] = 0;

    memcpy(p_rtp_data + 16, p_data, i_size);
    i_ret = (i_size + 16);

    return i_ret;
}

//buffer:接收到的数据；recv_bytes数据长度

int CmmbRtpToDRA(unsigned char *buffer, int recv_bytes, unsigned char* save_buffer, int* pnLastPkt)
{
    int save_len = 0; // 7 bytes adts head
    unsigned int nPkt = 0;
    nPkt = (unsigned int) (((buffer[2]) << 8) | (buffer[3]));

    if (nPkt - (*pnLastPkt) > 1)
    {
        printf("lose nPkt = %u, last = %u\n", nPkt, *pnLastPkt); //掉包。
    }
    if (nPkt<*(pnLastPkt))
    {
        //跳变
    }
    (*pnLastPkt) = nPkt;

    if (buffer[12] == 0xff)
    {
        //printf("AAC --------------\n");
        memcpy(&(save_buffer[0]), &(buffer[13]), recv_bytes - 13);
        save_len += (recv_bytes - 13);
    }
    else
    {
        //printf("DRA --------------\n");
        memcpy(&(save_buffer[0]), &(buffer[12]), recv_bytes - 12);
        save_len += (recv_bytes - 12);
    }

    /*
            int cur_idx = 0;
            unsigned char Framedata[4096]= { 0 };
            int FrameLen = 0;
            int i=0;

            while (LoadDraFrame1(save_buffer, save_len, &cur_idx, Framedata, &FrameLen))
        {
                    if (draFrameTopcm(pDraDecoder, Framedata, FrameLen, PcmBuf, &PcmBufLen)!=0) {
                            printf("dratopcm error\n");
                            continue;
                    }

                    printf("save_len = %d, PcmBufLen = %d\n", save_len, PcmBufLen);

                    // ***********pcm to mp2**************
                    aout_buffer_t buf;
                    memset(&buf, 0x00, sizeof(buf));
                    buf.p_buffer = PcmBuf;
                    buf.i_size = PcmBufLen;
                    buf.i_nb_samples = 1024;
    //		buf.i_nb_samples = buf.i_size / 4;
                    enc.pf_encode_audio(&enc, &buf);

                    printf("p_enc->i_samples_delay = %d, %d\n", enc.i_samples_delay,
                                    enc.p_context->frame_size);
                    printf("i_buffer_use=%d\n", enc.i_buffer_use);

                    // ***********rtsp_add_audio_frame**************
                    rtsp_add_audio_frame1(&myrtsp, enc.p_buffer_out, enc.i_buffer_use,
                                    enc.i_codec_id, enc.i_pts);

                    i++;
                    printf("Frame %d", i);

            }


     */
    //printf("AAC  %x, %x, %x\n", save_buffer[0], save_buffer[1], save_buffer[2]);
    //save_buffer[0] = (char)0xff;
    //save_buffer[1] = (char)0xf9;
    //save_buffer[2] = (0x01<<6)|(0x06<<2)|0x00; //0x06  means  24000Hz  ; 0x03  means 48000Hz can not play
    //save_buffer[3] = (char)0x80;  //双声道？ a=rtpmap:97 mpeg4-generic/44100/2
    //															//单声道？(char)0x40;    a=rtpmap:97 mpeg4-generic/44800
    //save_buffer[4] = (save_len>>3)&0xff;
    //save_buffer[5] = ((save_len&0x07)<<5|0x1f);
    //save_buffer[6] = (char)0xfc;
    return save_len;
}

int SetPortReuse(SOCKET sock, int bReuse)
{
    int value = bReuse ? 1 : 0;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*) &value, sizeof (value)) < 0)
    {
        printf("setsockopt:SO_REUSEADDR failed - %s\n", strerror(errno));
        return 0;
    }
    else
    {
        return 1;
    }
}

int JoinGroup(SOCKET sock, const char* strGroupIP)
{
    //sprintf("begin jion group\n");
    struct ip_mreq mreq;

    mreq.imr_multiaddr.s_addr = inet_addr(strGroupIP);

    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof (struct ip_mreq)) < 0)
    {
        return -1;
    }
    printf("JoinGroup:%s\n", strGroupIP);
    return 0;
}

int threadCreate(THREAD* funcThread, void* param)
{
    pthread_attr_t attr;
    pthread_t Thrd;
    struct sched_param SchedParam;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
    sched_getparam(0, &SchedParam);
    SchedParam.sched_priority = sched_get_priority_max(SCHED_FIFO);
    pthread_attr_setschedparam(&attr, &SchedParam);

    int s = pthread_create(&Thrd, &attr, funcThread, param);
    if (s != 0)
    {
        printf("threadCreate failed.\n");
        //handle_error_en(s, "pthread_create");
    }

    return 0;
}

void MP4_Dump(const char* pMP4File)
{
    MP4FileHandle file = MP4Read(pMP4File, 0);
    char* p = (char*) malloc(strlen(pMP4File) + 5);
    sprintf(p, "%s.dump", pMP4File);
    FILE* fp = fopen(p, "wb");

    if (file == MP4_INVALID_FILE_HANDLE || fp == NULL)
    {
        printf("dump file '%s' failed.file:0X%x, fp:0X%x\n", pMP4File, file, fp);
        return;
    }

    MP4Dump(file, fp, 1);
    fclose(fp);
    MP4Close(file);
}

static void* writeThread(void* arg)
{
    //MP4_Dump("/home/chu/a.mp4");
    rtp_s* p_rtp = (rtp_s*) arg;
    if (p_rtp == NULL)
    {
        printf("ERROR!\n");
        return;
    }

    MP4FileHandle file = MP4CreateEx("test.mp4", MP4_DETAILS_ALL, 0, 1, 1, 0, 0, 0, 0);
    //MP4FileHandle file = MP4Create("test.mp4", MP4_DETAILS_ALL, 0);
    if (file == MP4_INVALID_FILE_HANDLE)
    {
        printf("open file fialed.\n");
        return;
    }

    MP4SetTimeScale(file, 90000);

    //MP4TrackId video = MP4AddVideoTrack(file, 90000, 90000/25, 320, 240, MP4_MPEG4_VIDEO_TYPE);
    //MP4TrackId video = MP4AddH264VideoTrack(file, 90000, 3000, 320, 240,1, 2, 3, 1);
    //MP4TrackId video = MP4AddH264VideoTrack(file, 400000, 400000/25, 320, 240,1, 2, 3, 1);
    MP4TrackId video = MP4AddH264VideoTrack(file, 90000, 90000 / 25, 320, 240,
                                            0x64, //sps[1] AVCProfileIndication
                                            0x00, //sps[2] profile_compat
                                            0x1f, //sps[3] AVCLevelIndication
                                            3); // 4 bytes length before each NAL unit
    if (video == MP4_INVALID_TRACK_ID)
    {
        printf("add video track fialed.\n");
        return;
    }
    MP4SetVideoProfileLevel(file, 0x7F);

    //MP4_MPEG4_AAC_MAIN_AUDIO_TYPE
    MP4TrackId audio = MP4AddAudioTrack(file, 48000, 2048, MP4_MPEG4_AUDIO_TYPE);
    if (video == MP4_INVALID_TRACK_ID)
    {
        printf("add audio track fialed.\n");
        return;
    }
    MP4SetAudioProfileLevel(file, 0x2);


    int ncount = 0;
    while (1)
    {
        frame_t* pf = NULL; //frame
        pthread_mutex_lock(&p_rtp->mutex);
        pf = p_rtp->p_frame_header;
        if (pf != NULL)
        {
            if (pf->i_type == 1)//video
            {
                if(pf->i_frame_size >= 4)
                {
                    uint32_t* p = (&pf->p_frame[0]);
                    *p = htonl(pf->i_frame_size -4);
                }
                dump_frame(pf->p_frame, pf->i_frame_size);
               MP4WriteSample(file, video, pf->p_frame, pf->i_frame_size, MP4_INVALID_DURATION, 0, 1);
             }
            else if (pf->i_type == 2)//audio
            {
                //dump_frame(pf->p_frame, pf->i_frame_size);
                MP4WriteSample(file, audio, pf->p_frame, pf->i_frame_size , MP4_INVALID_DURATION, 0, 1);
            }

            ncount++;

            //clear frame.
            p_rtp->i_buf_num--;
            p_rtp->p_frame_header = pf->p_next;
            if (p_rtp->i_buf_num <= 0)
            {
                p_rtp->p_frame_buf = p_rtp->p_frame_header;
            }
            free_frame(&pf);
            pf = NULL;

            if (ncount >= 1000)
            {
                break;
            }
        }
        else
        {
            //printf("BUFF EMPTY, p_rtp->i_buf_num:%d\n", p_rtp->i_buf_num);
        }
        pthread_mutex_unlock(&p_rtp->mutex);
        usleep(10000);
    }

    //MP4Dump(file, NULL, 1);
    MP4Close(file);
    exit(0);
}

static void* writeThread2(void* arg)
{
    rtp_s* p_rtp = (rtp_s*) arg;
    if (p_rtp == NULL)
    {
        printf("ERROR!\n");
        return;
    }

    FILE* fileHandler = NULL;
    FILE* fp_H264 = fopen("Video.h264", "wb");
    FILE* fp_AAC = fopen("Audio.AAC", "wb");

    if (fp_H264 == NULL || fp_AAC == NULL)
    {
        printf("open file fialed.\n");
        return;
    }

    while (1)
    {
        frame_t* pf = NULL; //frame
        pthread_mutex_lock(&p_rtp->mutex);
        pf = p_rtp->p_frame_header;
        if (pf != NULL)
        {
            fileHandler = (pf->i_type == 1 ? fp_H264 : fp_AAC);
            //fileHandler = fp_H264;
            if (fileHandler == NULL)//invalid tye
                continue;

            size_t nwrote = fwrite(pf->p_frame, 1, pf->i_frame_size, fileHandler);
            printf("%s wrote:%d, p_rtp->i_buf_num:%d\n", pf->i_type == 1 ? "video" : "audio", nwrote, p_rtp->i_buf_num);

            //clear frame.
            p_rtp->i_buf_num--;
            p_rtp->p_frame_header = pf->p_next;
            if (p_rtp->i_buf_num <= 0)
            {
                p_rtp->p_frame_buf = p_rtp->p_frame_header;
            }
            free_frame(&pf);
            pf = NULL;
        }
        else
        {
            printf("BUFF EMPTY, p_rtp->i_buf_num:%d\n", p_rtp->i_buf_num);
        }
        pthread_mutex_unlock(&p_rtp->mutex);
        usleep(10000);
    }

    fclose(fp_H264);
    fclose(fp_AAC);
}

static int clear_frame(rtp_s* p_rtp)
{
    frame_t* p_temp = NULL;
    pthread_mutex_lock(&p_rtp->mutex);

    while (p_rtp->p_frame_header != NULL)
    {
        p_temp = p_rtp->p_frame_header->p_next;
        free_frame(&p_rtp->p_frame_header);
        p_rtp->p_frame_header = p_temp;
    }
    p_rtp->p_frame_buf = NULL;
    p_rtp->p_frame_header = NULL;
    p_rtp->i_buf_num = 0;
    pthread_mutex_unlock(&p_rtp->mutex);
    return 0;
}


static int add_frame(rtp_s* p_rtp, uint8_t* p_frame, uint32_t i_size, uint32_t i_type, uint64_t i_stamp, uint32_t i_flag)
{
    printf("Add frame:%s[%d]\n", (i_type == 1 ? "Video" : "Audio"), i_size);
    int i_ret = 0;

    //printf("add frame, i_type = %d, i_stamp = %u\n", i_type, i_stamp);
    if (p_rtp->i_buf_num > 400)
    {
        printf("rtp frame buf overlow, notice this\n");
    }
    else
    {
        //printf("Add frame\n");
        pthread_mutex_lock(&p_rtp->mutex);
        if (p_rtp->p_frame_buf == NULL)
        {
            p_rtp->p_frame_buf = new_frame(p_frame, i_size, i_type, i_stamp);
            p_rtp->p_frame_header = p_rtp->p_frame_buf;
            p_rtp->p_frame_buf->i_flag = i_flag;
        }
        else
        {
            frame_t* p_new = new_frame(p_frame, i_size, i_type, i_stamp);
            p_new->i_flag = i_flag;
            p_rtp->p_frame_buf->p_next = p_new;
            p_rtp->p_frame_buf = p_new;
            //printf("%x, header = %x\n", p_rtp->p_frame_buf, p_rtp->p_frame_header);
        }

        /*
        if ((p_rtp->p_frame_buf->p_frame[3]&0x1F) != 1)
        {
            printf("%x, %d\n", p_rtp->p_frame_buf->p_frame[3], i_size);
        }
         */

        //static FILE* file = NULL;
        //		if (file == NULL)
        //		{
        ///*
        //			if (p_rtp->p_frame_buf->p_frame[0] == 0 &&
        //				p_rtp->p_frame_buf->p_frame[1] == 0 &&
        //				p_rtp->p_frame_buf->p_frame[2] == 1 &&
        //				(p_rtp->p_frame_buf->p_frame[3]&0x1F) == 0x07)
        //
        //			{
        //				file = fopen("111111.h264", "w");
        //				char cTemp = 0;
        //				fwrite(&cTemp, 1, 1, file);
        //			}
        //		}
        //		if (file != NULL)
        //		{
        //			//printf("------------%x %x %x %x\n", p_rtp->p_frame_buf->p_frame[0], p_rtp->p_frame_buf->p_frame[1],
        //			//	p_rtp->p_frame_buf->p_frame[2], p_rtp->p_frame_buf->p_frame[3]);
        //			fwrite(p_rtp->p_frame_buf->p_frame, 1, p_rtp->p_frame_buf->i_frame_size, file);
        //			//fwrite(p_save_buf, 1, i_size, file);
        //		}

        p_rtp->i_buf_num++;
        pthread_mutex_unlock(&p_rtp->mutex);
    }

    return i_ret;
}

static int free_frame(frame_t** pp_frame)
{
    if ((*pp_frame) != NULL)
    {
        free((*pp_frame));
        (*pp_frame) = NULL;
    }
    return 0;
}

static frame_t* new_frame(uint8_t* p_frame_data, uint32_t i_size, uint32_t i_type, uint64_t i_stamp)
{
    int i_ret = 0;
    frame_t* p_new = NULL;
    if (p_frame_data == NULL || i_size <= 0)
    {
        i_ret = -1;
    }
    else
    {
        p_new = malloc(i_size + sizeof (frame_t));
        if (p_new == NULL)
        {
            printf("malloc rtp frame error\n");
            i_ret = -1;
        }
        else
        {
            p_new->p_frame = ((uint8_t*) p_new) + sizeof (frame_t);

            p_new->i_frame_size = i_size;
            p_new->i_type = i_type;
            p_new->i_time_stamp = i_stamp;
            p_new->p_next = NULL;
            memcpy(p_new->p_frame, p_frame_data, i_size);
        }
    }

    if (i_ret < 0)
    {
        return NULL;
    }
    else
    {
        return p_new;
    }
}

static int dump_frame(uint8_t* p_frame, uint32_t size)
{
    printf("*********************************************************:%u\n", size);
    if(p_frame != NULL && size >0)
    {
        uint32_t i=0;
        for(; i<size; i++)
        {
            printf("%x ", p_frame[i]);

            if((i+1)%32 == 0)
            {
                printf("\n");
            }
        }
    }
    printf("\n");
}
