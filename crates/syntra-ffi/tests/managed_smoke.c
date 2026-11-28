#define _POSIX_C_SOURCE 200809L
#include "syntra_managed.h"
#include <assert.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#define OK(expr) assert((expr) == SYNTRA_OK)
#define VIEW(a) (syntra_view_t){(const uint8_t *)(a), sizeof(a) - 1}
static void tick(void) { nanosleep(&(struct timespec){0, 1000000}, NULL); }

static uint64_t ready(syntra_managed_t *h, uint64_t id, uint32_t lane) {
    syntra_lane_status_t s;
    for (unsigned i=0;i<5000;i++,tick()) {
        OK(syntra_managed_status(h,id,lane,&s));
        if (s.state == SYNTRA_MANAGED_READY) { assert(s.generation); return s.generation; }
    }
    assert(!"lane readiness timeout"); return 0;
}
static syntra_managed_result_t take(syntra_managed_t *h, uint64_t id, uint64_t token) {
    syntra_managed_result_t r;
    int rc;
    do { rc=syntra_managed_poll(h,id,token,&r); if(rc==SYNTRA_PENDING) tick(); } while(rc==SYNTRA_PENDING);
    OK(rc); return r;
}
static void close_owner(syntra_managed_t *h,uint64_t id) {
    OK(syntra_managed_shutdown(h,id));
    int rc;
    do { rc=syntra_managed_shutdown_poll(h,id); if(rc==SYNTRA_SHUTDOWN_INCOMPLETE) tick(); } while(rc==SYNTRA_SHUTDOWN_INCOMPLETE);
    OK(rc); OK(syntra_managed_destroy(h,id));
}
static void rejected_key(syntra_managed_config_t c) {
    uint8_t other[32]={11}; c.authorization_key=(syntra_view_t){other,sizeof other};
    syntra_managed_t *h; uint64_t id;
    OK(syntra_managed_open(1,&c,&h,&id));
    for (;;) {
        syntra_lane_status_t s; OK(syntra_managed_status(h,id,1,&s));
        assert(s.state!=SYNTRA_MANAGED_READY && !s.generation);
        if(s.state==SYNTRA_MANAGED_BLOCKED || s.state==SYNTRA_MANAGED_EXHAUSTED) break;
        tick();
    }
    close_owner(h,id);
}
static void capacity(syntra_managed_t *h,uint64_t id) {
    /* Each unread call reserves a maximum frame PLUS the method and payload.
     * The 32 MiB byte budget binds before the 32-operation count limit. */
    uint64_t jobs[31],extra;
    for (size_t i=0;i<31;i++) OK(syntra_managed_call(h,id,1,VIEW("/fixture.Echo/Echo"),VIEW("x"),2000,&jobs[i]));
    assert(syntra_managed_call(h,id,1,VIEW("/fixture.Echo/Echo"),VIEW("x"),2000,&extra)==SYNTRA_BUSY && !extra);
    for (size_t i=0;i<31;i++) { syntra_managed_result_t r=take(h,id,jobs[i]); syntra_free(r.data.data,r.data.len); }
}

struct sink_state { atomic_int entered, release; };
static int32_t chunk(uintptr_t ctx,const uint8_t *p,uintptr_t len) {
    struct sink_state *state=(struct sink_state *)ctx;
    assert(len==3 && !memcmp(p,"abc",3));
    atomic_store(&state->entered,1);
    /* Deliberate fixture gate: verify that cancellation or shutdown cannot
     * declare completion while this foreign context is still in use. */
    while(!atomic_load(&state->release)) tick();
    return 0;
}

static void transfers(syntra_managed_t *h,uint64_t id) {
    syntra_manifest_t m={.version=1,.length=3,.transfer_id={2},.sha256={
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad}};
    memset(m.object,1,sizeof m.object);
    FILE *f=fopen("source","wb"); assert(f && fwrite("abc",1,3,f)==3 && !fclose(f));
    uint64_t token=0;
    OK(syntra_managed_upload(h,id,&m,VIEW("source"),&token));
    syntra_managed_result_t r=take(h,id,token); assert(!r.grpc_code && !r.data.data);
    struct sink_state state={0,1};
    syntra_sink_t sink={(uintptr_t)&state,chunk};
    OK(syntra_managed_download(h,id,&m,VIEW("dest.db"),VIEW("authority/account"),sink,&token));
    r=take(h,id,token); assert(!r.grpc_code && atomic_load(&state.entered));
    atomic_store(&state.entered,0); atomic_store(&state.release,0);
    OK(syntra_managed_download(h,id,&m,VIEW("dest.db"),VIEW("authority/account"),sink,&token));
    while(!atomic_load(&state.entered)) tick();
    syntra_progress_t progress; OK(syntra_managed_progress(h,id,token,&progress));
    assert(progress.object_bytes==3 && progress.completed_rpcs && progress.response_bytes);
    uint64_t second,extra;
    OK(syntra_managed_upload(h,id,&m,VIEW("source"),&second));
    assert(syntra_managed_upload(h,id,&m,VIEW("source"),&extra)==SYNTRA_BUSY && !extra);
    r=take(h,id,second); assert(!r.grpc_code); /* explicit resume of committed object */
    OK(syntra_managed_cancel(h,id,token));
    assert(syntra_managed_poll(h,id,token,&r)==SYNTRA_PENDING);
    OK(syntra_managed_shutdown(h,id));
    assert(syntra_managed_shutdown_poll(h,id)==SYNTRA_SHUTDOWN_INCOMPLETE);
    atomic_store(&state.release,1);
    r=take(h,id,token); assert(r.grpc_code==1 || r.grpc_code==0);
    assert(syntra_managed_progress(h,id,token,&progress)==SYNTRA_STALE);
}
#include "managed_fixture/resume.h"
int main(int argc, char **argv) {
    assert(argc==3);
    assert(syntra_abi_version()==1 && syntra_capabilities()==13);
    uint8_t pin[32], ak[32], handle[8];
    memset(ak,3,sizeof ak); memset(handle,4,sizeof handle);
    assert(fread(pin,1,sizeof pin,stdin)==sizeof pin);
    syntra_managed_config_t c={
        .address={(uint8_t *)argv[1],strlen(argv[1])},.scope=VIEW("ffi-loopback"),
        .server_pin={pin,sizeof pin},.credential=VIEW("fixture-hello"),
        .mode=SYNTRA_MANAGED_RETURNING,.server_key_id=23,.epoch=17,
        .handle={handle,sizeof handle},.authorization_key={ak,sizeof ak}
    };
    if(strcmp(argv[2],"smoke")) { resume_stage(c,argv[2]); return 0; }
    syntra_managed_t *h=NULL; uint64_t id=0, t=0;
    assert(syntra_managed_open(2,&c,&h,&id)==SYNTRA_ABI_MISMATCH && !h && !id);
    c.authorization_key.len--;
    assert(syntra_managed_open(1,&c,&h,&id)==SYNTRA_INVALID && !h && !id);
    c.authorization_key.len++;
    rejected_key(c);
    OK(syntra_managed_open(1,&c,&h,&id));
    memset(&c,0,sizeof c); memset(ak,0,sizeof ak); memset(pin,0,sizeof pin); memset(handle,0,sizeof handle);
    syntra_lane_status_t s;
    assert(syntra_managed_status(h,id+1,1,&s)==SYNTRA_STALE);
    syntra_update_status_t us; OK(syntra_managed_update_status(h,id,&us));
    assert(us.state==SYNTRA_UPDATES_DISABLED && !us.generation);
    assert(syntra_managed_status(h,id,99,&s)==SYNTRA_INVALID);
    for(uint32_t lane=1;lane<=2;lane++) {
        syntra_managed_result_t r;
        if(lane==SYNTRA_MANAGED_INTERACTIVE) {
            const uint64_t g=ready(h,id,lane);
            OK(syntra_managed_next_notification(h,id,lane,&t)); r=take(h,id,t);
            assert(!r.grpc_code && r.has_data && r.generation==g && r.data.len==10 && !memcmp(r.data.data,"lane-ready",10));
            syntra_free(r.data.data,r.data.len);
            OK(syntra_managed_control(h,id,SYNTRA_MANAGED_PAUSE));
            OK(syntra_managed_control(h,id,SYNTRA_MANAGED_RESUME));
            uint64_t next=0;
            while(next==0 || next==g) { next=ready(h,id,lane); if(next==g) tick(); }
            capacity(h,id);
        } else assert(syntra_managed_next_notification(h,id,lane,&t)==SYNTRA_INVALID);
        char buf[]="a\0b";
        int rc;
        do { rc=syntra_managed_call(h,id,lane,VIEW("/fixture.Echo/Echo"),VIEW(buf),2000,&t);
            if(rc==SYNTRA_PENDING || rc==SYNTRA_BUSY) { assert(!t); tick(); }
        } while(rc==SYNTRA_PENDING || rc==SYNTRA_BUSY);
        OK(rc);
        memset(buf,0,sizeof buf);
        r=take(h,id,t);
        assert(!r.grpc_code && r.generation==ready(h,id,lane) && r.data.len==3 && !memcmp(r.data.data,"a\0b",3));
        syntra_free(r.data.data,r.data.len);
        assert(syntra_managed_poll(h,id,t,&r)==SYNTRA_STALE);
    }
    assert(syntra_managed_call(h,id,1,VIEW("/fixture.Echo/Echo"),(syntra_view_t){NULL,SIZE_MAX},2000,&t)==SYNTRA_INVALID && !t);
    assert(syntra_managed_destroy(h,id)==SYNTRA_SHUTDOWN_INCOMPLETE);
    transfers(h,id);
    OK(syntra_managed_shutdown(h,id));
    assert(syntra_managed_next_notification(h,id,1,&t)==SYNTRA_CLOSED && !t);
    close_owner(h,id);
}
