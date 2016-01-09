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
#include <private/media/AudioTrackShared.h>
#include <binder/IPCThreadState.h>
#include <media/AudioPolicyHelper.h>
#include <media/AudioResamplerPublic.h>
#include <utils/Log.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

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

void threadFuncBlaster(Irrc* _this)
{
	int ret = 0;
	sp<AudioTrack> track = new android::AudioTrack();

	int mintime = LG_IRRC_EWG_SetMinTime(200);
	int ewgInit = LG_IRRC_EWG_Init(mintime);

	if (ewgInit != 1)
		ALOGE("EWG : initial fail %d -- ", ewgInit);
        else
		ALOGI("EWG : initial success %d -- ", ewgInit);

        ALOGI("LGIr: SetAudioTrack");
	ret = track->set(AUDIO_STREAM_MUSIC,
                   48000,
                   AUDIO_FORMAT_PCM_16_BIT,
                   AUDIO_CHANNEL_OUT_STEREO,
                   0,
                   (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_IRRC | AUDIO_OUTPUT_FLAG_DIRECT));
	if (ret) {
	      ALOGE("LGIr: Track set fail");
	      return;
	}
        ALOGI("LGIr: Create AudioBuffer");
        audioBuf = new AudioTrack::Buffer();

	_this->blaster = 1;

        ALOGI("LGIr: Drop cond wait in parent");
        pthread_cond_signal(&_this->cond);
        usleep(250000);

        ALOGI("LGIr: Start Clear audio buffer");
        track->start();

        memset(trackdata, 0, 2048);
        for (int i = 0; i < 3; i++) {
             int written = track->write(trackdata, 2048, true);
             ALOGI("LGIr, clear buffer: %d", written);
        }

        ALOGI("LGIr: Start LG_IRRC_EWG_Processing: %d, %d", iTotalFrameLength, iChannelCount);
        while (true) {
             LGProcRes = LG_IRRC_EWG_Processing(trackdata, iTotalFrameLength, iChannelCount, runStatus);
             int written = track->write(trackdata, 2048, true);
             ALOGI("LGIr: written %d <%d, %d>", written, LGProcRes, runStatus);
             if (LGProcRes == 6 || trackStatus == 8) {
                 ALOGI("LGIr: LGProcRes: %d, trackStatus: %d", LGProcRes, trackStatus);
                 break;
             }
        }

        ALOGI("LGIr, Send IOCTL");
        int val = 0;
        int fd = -1;
        if ((fd = open("/dev/msm_IRRC_pcm_dec", O_RDWR)) < 0)
           ALOGI("Error open /msm_IRRC_pcm_dec");

        if (ioctl(fd, IRRC_STOP, &val) < 0)
           ALOGI("Error call IRRC_STOP ioctl");

        close(fd);

        ALOGI("LGIr: AudioTrack Stop");
        track->stop();

        ALOGI("Set track status to 0");
	_this->blaster = 0;
        trackStatus = 0;

        ALOGI("LGIr: Delete Audio Buffer");
        delete audioBuf;
        pthread_cond_signal(&_this->cond);

        ALOGI("LGIr: Delete Audio Track");
        //delete track;
        track->flush();
	track.clear();
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

