/*
 * Copyright (C) 2016 Nickolay Semendyaev <agent00791@gmail.com>
 * Copyright (C) 2016 Balázs Triszka <balika011@protonmail.ch>
 *
 * LG Ir blobs support layer for android 6.0+
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <media/AudioTrack.h>
#include <utils/Log.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <system/audio.h>
#include <tinyalsa/asoundlib.h>

int memcpy_protect(void* to, void* from, int len)
{
    int result = 0;

    if (len)
    {
        unsigned char *to_page = (unsigned char *)((unsigned int)(to) & 0xFFFFF000);
        size_t page_size = 0;

        for(int i = 0, j = 0; i < len; ++i)
        {
            page_size = j * 4096;
            if ( &((unsigned char *)(to))[i] >= &to_page[page_size])
                ++j;
        }

        result = mprotect(to_page, page_size, 7);
        memcpy(to, from, len);
    }

    return result;
}

void ARMBIGJMP(void* from, void* to)
{
    unsigned char hookdata[] =
    {
        0x01, 0xB4,             // PUSH {R0}
        0x01, 0xB4,             // PUSH {R0}
        0x01, 0x48,             // LDR  R0, ADDR
        0x01, 0x90,             // STR  R0, [SP,#8+var_4]
        0x01, 0xBD,             // POP  {R0,PC}
        0x00, 0xBF,             // NOP
        0x00, 0x00, 0x00, 0x00  // ADDR
    };

    *(unsigned long *)&hookdata[12] = (unsigned long)(to);

    memcpy_protect((void*)((unsigned long)(from) & 0xFFFFFFFE), hookdata, 16);
}

#define IRRC_IOCTL_MAGIC 'a'
#define IRRC_START        _IOW(IRRC_IOCTL_MAGIC, 0, int)
#define IRRC_STOP         _IOW(IRRC_IOCTL_MAGIC, 1, int)

namespace android {
// Reversed form LG's proprietary Ir blobs.
class IIrrc //its based on android::Interface
{
//private:
public:
	BBinder binder;
	int state;

public:
	IIrrc();
	virtual ~IIrrc();
	//TODO: ...
};

class Irrc : IIrrc
{
//private:
public:
	int blaster;
	pthread_cond_t cond;
	int mutex;
	int mThread;
	int field_2C;
	int field_30;

public:
	Irrc();
	virtual ~Irrc();
	//TODO: ...
};

extern "C" int trackStatus;
// These lines are hack. If you dont like them, then re the full blob ;)
#define runStatus *(int *)(((char *) &trackStatus) - 0xB004 + 0xB028) //int runStatus;
#define LGProcRes *(int *)(((char *) &trackStatus) - 0xB004 + 0xB02C) //int LGProcRes;
#define trackdata (((char *) &trackStatus) - 0xB004 + 0xB030) //char trackdata[2048];
extern int iTotalFrameLength;
extern int iChannelCount;
extern "C" int LG_IRRC_EWG_SetMinTime(int val);
extern "C" int LG_IRRC_EWG_Init(int val);
extern "C" int LG_IRRC_EWG_Processing(char* audioBuffer, int iTotalFrameLength, int iChannelCount, int status);
extern AudioTrack::Buffer *audioBuf;


/*
    <!-- LGE devices IRRC -->
    <path name="lg-irrc-playback">
        <ctl name="SLIMBUS_0_RX Audio Mixer MultiMedia2" value="1" />
    </path>

    <path name="lg-irrc-lineout">
        <ctl name="SLIM RX1 MUX" value="AIF1_PB" />
        <ctl name="SLIM_0_RX Channels" value="One" />
        <ctl name="RX3 MIX1 INP1" value="RX1" />
        <ctl name="RX3 Digital Volume" value="88" />
        <ctl name="LINEOUT1 Volume" value="20" />
        <ctl name="SPK DAC Switch" value="0" />
    </path>
*/
#define ISLIMBUS_0_RX "SLIMBUS_0_RX Audio Mixer MultiMedia2"
#define SLIM_RX1_MUX "SLIM RX1 MUX"
#define RX3_MIX1_INP1 "RX3 MIX1 INP1"
#define SLIM_0_RX_Channels "SLIM_0_RX Channels"
#define RX3_Digital_Volume "RX3 Digital Volume"
#define LINEOUT1_Volume "LINEOUT1 Volume"
#define SPK_DAC_Switch "SPK DAC Switch"

static int configure_mixers()
{
    enum mixer_ctl_type type;
    struct mixer_ctl *ctl;
    struct mixer *mixer = mixer_open(0);

    if (mixer == NULL) {
        ALOGE("Error opening mixer 0");
        return -1;
    }

//SLIMBUS_0_RX Audio Mixer MultiMedia2
    ctl = mixer_get_ctl_by_name(mixer, ISLIMBUS_0_RX);
    if (ctl == NULL) {
        mixer_close(mixer);
        ALOGE("%s: Could not find %s\n", __func__, ISLIMBUS_0_RX);
        return -ENODEV;
    }

    type = mixer_ctl_get_type(ctl);
    if (type != MIXER_CTL_TYPE_BOOL) {
        ALOGE("%s: %s is not supported\n", __func__, ISLIMBUS_0_RX);
        mixer_close(mixer);
        return -ENOTTY;
    }
    mixer_ctl_set_value(ctl, 0, 1);

//SLIM RX1 MUX
    ctl = mixer_get_ctl_by_name(mixer, SLIM_RX1_MUX);
    if (ctl == NULL) {
        mixer_close(mixer);
        ALOGE("%s: Could not find %s\n", __func__, SLIM_RX1_MUX);
        return -ENODEV;
    }

    type = mixer_ctl_get_type(ctl);
    mixer_ctl_set_enum_by_string(ctl, "AIF1_PB");

//SLIM_0_RX Channels
    ctl = mixer_get_ctl_by_name(mixer, SLIM_0_RX_Channels);
    if (ctl == NULL) {
        mixer_close(mixer);
        ALOGE("%s: Could not find %s\n", __func__, SLIM_0_RX_Channels);
        return -ENODEV;
    }

    type = mixer_ctl_get_type(ctl);
    mixer_ctl_set_enum_by_string(ctl, "One");

//RX3_MIX1_INP1
    ctl = mixer_get_ctl_by_name(mixer, RX3_MIX1_INP1);
    if (ctl == NULL) {
        mixer_close(mixer);
        ALOGE("%s: Could not find %s\n", __func__, RX3_MIX1_INP1);
        return -ENODEV;
    }

    type = mixer_ctl_get_type(ctl);
    mixer_ctl_set_enum_by_string(ctl, "RX1");


//RX3_Digital_Volume
    ctl = mixer_get_ctl_by_name(mixer, RX3_Digital_Volume);
    if (ctl == NULL) {
        mixer_close(mixer);
        ALOGE("%s: Could not find %s\n", __func__, RX3_Digital_Volume);
        return -ENODEV;
    }

    type = mixer_ctl_get_type(ctl);
    if (type != MIXER_CTL_TYPE_INT) {
        ALOGE("%s: %s is not supported\n", __func__, RX3_Digital_Volume);
        mixer_close(mixer);
        return -ENOTTY;
    }
    mixer_ctl_set_value(ctl, 0, 88);

//LINEOUT1 Volume
    ctl = mixer_get_ctl_by_name(mixer, LINEOUT1_Volume);
    if (ctl == NULL) {
        mixer_close(mixer);
        ALOGE("%s: Could not find %s\n", __func__, LINEOUT1_Volume);
        return -ENODEV;
    }

    type = mixer_ctl_get_type(ctl);
    if (type != MIXER_CTL_TYPE_INT) {
        ALOGE("%s: %s is not supported\n", __func__, LINEOUT1_Volume);
        mixer_close(mixer);
        return -ENOTTY;
    }
    mixer_ctl_set_value(ctl, 0, 20);

//SPK DAC Switch
    ctl = mixer_get_ctl_by_name(mixer, SPK_DAC_Switch);
    if (ctl == NULL) {
        mixer_close(mixer);
        ALOGE("%s: Could not find %s\n", __func__, SPK_DAC_Switch);
        return -ENODEV;
    }

    type = mixer_ctl_get_type(ctl);
    if (type != MIXER_CTL_TYPE_BOOL) {
        ALOGE("%s: %s is not supported\n", __func__, SPK_DAC_Switch);
        mixer_close(mixer);
        return -ENOTTY;
    }
    mixer_ctl_set_value(ctl, 0, 0); //Disable speaker,

    mixer_close(mixer);
    return 0;
}

#define DEFAULT_OUTPUT_SAMPLING_RATE 48000
#define LOW_LATENCY_OUTPUT_PERIOD_SIZE 256 //audio hal 240
#define LOW_LATENCY_OUTPUT_PERIOD_COUNT 2

void threadFuncBlaster(Irrc* _this)
{
	int ret = 0;
        int fd = -1;
	char buffer[2048];
        unsigned int flags = PCM_OUT;
        int size;

        struct pcm *pcm;
        struct pcm_config config = {  //From audio hal
                .channels = 2,
                .rate = DEFAULT_OUTPUT_SAMPLING_RATE,
                .period_size = LOW_LATENCY_OUTPUT_PERIOD_SIZE,
                .period_count = LOW_LATENCY_OUTPUT_PERIOD_COUNT,
                .format = PCM_FORMAT_S16_LE,
                .start_threshold = LOW_LATENCY_OUTPUT_PERIOD_SIZE / 4,
                .stop_threshold = INT_MAX,
                .avail_min = LOW_LATENCY_OUTPUT_PERIOD_SIZE / 4,
        };

        if (configure_mixers() != 0)
             goto err_2;

        flags |= PCM_MONOTONIC; //From audiohal

        pcm = pcm_open(0, 1, flags, &config); //From audiohal
        if (!pcm || !pcm_is_ready(pcm)) {
             ALOGE("pcm_open failed: %s", pcm_get_error(pcm));
             goto err_2;
        }

	if (LG_IRRC_EWG_Init(LG_IRRC_EWG_SetMinTime(200)) != 1) {
             ALOGE("EWG : initial fail -- ");
             goto err_1;
        }

	ALOGI("EWG : initial success -- ");

	_this->blaster = 1;

        ALOGI("LGIr: Drop cond wait in parent");
        pthread_cond_signal(&_this->cond);
        usleep(250000);

// LOW_LATENCY_OUTPUT_PERIOD_COUNT (256) * LOW_LATENCY_OUTPUT_PERIOD_SIZE (2) * 4 == 2048
        size = pcm_frames_to_bytes(pcm, pcm_get_buffer_size(pcm));
        memset(buffer, 0, size);

        for (int i = 0; i < 4; i++) {
             if (pcm_write(pcm, buffer, size)) {
                 ALOGE("%s: pcm_write failed", __func__);
                 goto err_1;
             }
        }

        ALOGI("LGIr: Start LG_IRRC_EWG_Processing: %d, %d", iTotalFrameLength, iChannelCount);

        while (true) {

             LGProcRes = LG_IRRC_EWG_Processing(buffer, iTotalFrameLength, iChannelCount, runStatus);

             if (pcm_write(pcm, buffer, size)) {
                 ALOGE("%s: pcm_write failed", __func__);
                 goto err_1;
             }

             if (LGProcRes == 6 || trackStatus == 8) {
                 break;
             }
        }

        ALOGI("LGIr, Send Stop IOCTL");
        if ((fd = open("/dev/msm_IRRC_pcm_dec", O_RDWR)) < 0) {
           ALOGI("Error open /msm_IRRC_pcm_dec");
           goto err_1;
        }

        if (ioctl(fd, IRRC_STOP, &ret) < 0) {
           ALOGI("Error call IRRC_STOP ioctl");
        }

        close(fd);
err_1:
        pcm_close(pcm);
err_2:
	_this->blaster = 0;
        trackStatus = 0;
        pthread_cond_signal(&_this->cond);
}

extern "C" int _ZN7android4Irrc17threadFuncBlasterEv(Irrc* irrc);
extern "C" int _ZN7android4Irrc11instantiateEv(Irrc* irrc);
extern "C" int LGeInitIrDA(Irrc* irrc)
{
	ALOGI("LGIr: Init Service...");

	ARMBIGJMP((void *) _ZN7android4Irrc17threadFuncBlasterEv, (void *)threadFuncBlaster);

	return _ZN7android4Irrc11instantiateEv(irrc);
}

// Ignore this. Only needed to load libirrc.so
extern "C" int _ZN7android10AudioTrack3setE19audio_stream_type_tj14audio_format_tjj20audio_output_flags_tPFviPvS4_ES4_jRKNS_2spINS_7IMemoryEEEbiNS0_13transfer_typeEPK20audio_offload_info_tiiPK18audio_attributes_t() { return 0; }
}

