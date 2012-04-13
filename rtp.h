#ifndef RTP_H
#define RTP_H

#include "common.h"
#include "include/mp4v2.h"

#ifndef MUTEX
#define MUTEX pthread_mutex_t
#endif

#ifndef SOCKET
#define SOCKET int
#endif

#ifndef SOCKADDR_IN
#define SOCKADDR_IN struct sockaddr_in
#endif

#ifndef SOCKADDR
#define SOCKADDR struct sockaddr
#endif


#define MAX_RTP_TRAN_SIZE 		1200
#define MAX_VIDEO_FRAME_SIZE		409600
#define MAX_AUDIO_FRAME_SIZE		102400

typedef struct _frame_t
{
    int i_type; // 1-VIDEO, 2-AUDIO
    uint32_t i_frame_size;
    uint8_t* p_frame;
    uint64_t i_time_stamp;
    int i_flag;

    struct _frame_t* p_next;
} frame_t;

typedef struct _rtp_header_t
{
    uint8_t i_version;
    uint8_t i_extend;
    uint8_t i_m_tag;
    uint8_t i_cc;
    uint8_t i_pt;
    uint32_t i_seq_num;
    uint32_t i_timestamp;
    uint32_t i_ssrc;
    uint32_t i_csrc;

    uint8_t i_nalu_header;
} rtp_header_t;

typedef struct _rtp_s
{
    //视频缓冲区
    uint8_t* p_video_frame;
    uint32_t i_video_frame_index;
    uint32_t i_video_time_stamp;

    //音频缓冲区
    uint8_t* p_audio_frame;
    uint32_t i_audio_frame_index;
    uint32_t i_audio_time_stamp;

    uint32_t i_nalu_ok_flag;
    uint32_t i_last_pkt_num;

    uint32_t i_aui_last_pkt_num;

    uint32_t i_exit; // 0-正常 1-退出

    char p_ip[40];
    int i_port;

    void* p_opaque;

    //贞缓冲区,存放完整的音视频数据
    int i_buf_num;
    frame_t* p_frame_buf;
    frame_t* p_frame_header;
    MUTEX mutex;

    uint32_t i_video_time; // 调整原始流里面的视频时间戳
    uint32_t i_audio_time; // 调整原始流里面的音频时间戳

    uint16_t i_seq_num; // 序列号
} rtp_s;


int rtp_init(rtp_s* p_rtp, char* p_ip, int i_port);
int rtp_deinit(rtp_s* p_rtp);


int get_rtp_header(rtp_header_t* p_header, uint8_t* p_buf, uint32_t i_size);

//buffer:接收到的数据；recv_bytes数据长度
int RtpTo264(unsigned char* buffer, int recv_bytes, /*unsigned*/ char* save_buffer, uint32_t* pnNALUOkFlag, uint32_t* pnLastPkt);

//buffer:接收到的数据；recv_bytes数据长度
int CmmbRtpToAAC(unsigned char *buffer, int recv_bytes, char* save_buffer, uint32_t* pnLastPkt);

// i_nalu_flag: 0-未结束的帧，1-中间帧，2-结束的帧，3-完整的帧
int get_rtp_video_paket(unsigned char* p_data, int i_size, unsigned char* p_rtp_data, rtp_header_t* p_header, int i_nalu_flag);

int get_rtp_audio_paket(unsigned char* p_data, int i_size, unsigned char* p_rtp_data, rtp_header_t* p_header);

int get_rtp_aac_packet(unsigned char* p_data, int i_size, unsigned char* p_rtp_data, rtp_header_t* p_header);

#define PVOID void*
typedef PVOID THREAD(PVOID Arg);
int threadCreate(THREAD* funcThread, void* param);

#endif