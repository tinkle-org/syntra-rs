/* Included by the C consumer. The Rust host starts a fresh process for each
 * stage. The only shared application state is the source and durable files. */
struct app { atomic_int restored, applied; int successor; };

static int32_t restore(uintptr_t ctx, uint64_t g, const syntra_record_t *r) {
    struct app *app = (struct app *)ctx;
    assert(g && r->generation == 3 && r->checkpoint_len == 1 && r->application_state_len == 1);
    assert(r->checkpoint[0] == (app->successor ? 'b' : 'a'));
    assert(r->application_state[0] == (app->successor ? '2' : '1'));
    assert(!atomic_exchange(&app->restored, 1));
    return 0;
}
static int32_t apply_delta(uintptr_t ctx, uint64_t g, uint64_t batch_g,
        syntra_view_t prev, syntra_view_t next, syntra_view_t payload,
        uint8_t *full, uintptr_t capacity, uintptr_t *used) {
    struct app *app = (struct app *)ctx;
    assert(g && batch_g == 3 && atomic_load(&app->restored) && !app->successor);
    assert(prev.len == 1 && *prev.data == 'a' && next.len == 1 && *next.data == 'b');
    assert(payload.len == 2 && !memcmp(payload.data, "+1", 2) && capacity >= 1);
    full[0] = '2'; *used = 1;
    assert(!atomic_exchange(&app->applied, 1));
    return 0;
}

/* One writer, one scope, fixed G=3. Atomically replace the full two-byte
 * (checkpoint,state) file and sync the directory before attesting DURABLE. */
static void persist(const uint8_t record[2]) {
    FILE *f = fopen("record.tmp", "wb");
    assert(f && fwrite(record, 1, 2, f) == 2 && !fflush(f) && !fsync(fileno(f)) && !fclose(f));
    assert(!rename("record.tmp", "record"));
    int dir = open(".", O_RDONLY); assert(dir >= 0 && !fsync(dir) && !close(dir));
}
static int storage(syntra_managed_t *h, uint64_t id) {
    syntra_storage_request_t req;
    int rc = syntra_managed_storage_take(h, id, &req);
    if (rc == SYNTRA_PENDING) return 0;
    OK(rc);
    assert(req.principal_scope.len == 4 && !memcmp(req.principal_scope.data,"acct",4));
    assert(req.stable_stream.len == 4 && !memcmp(req.stable_stream.data,"feed",4));
    uint8_t old[2]; FILE *f = fopen("record", "rb");
    assert(f && fread(old,1,2,f)==2 && fgetc(f)==EOF && !ferror(f) && !fclose(f));
    int committed = 0;
    if (req.kind == SYNTRA_STORAGE_LOAD) {
        syntra_record_t r = {3, old, 1, old+1, 1};
        OK(syntra_managed_storage_complete(h,id,req.token,SYNTRA_STORAGE_FOUND,&r));
    } else {
        assert(req.kind == SYNTRA_STORAGE_CAS_COMMIT && req.generation == 3 && req.expected_present);
        assert(req.expected_generation == 3 && req.expected_checkpoint.len == 1 && old[0] == *req.expected_checkpoint.data);
        assert(req.checkpoint.len == 1 && req.application_state.len == 1);
        uint8_t next[2] = {*req.checkpoint.data, *req.application_state.data};
        assert(!memcmp(old,"a1",2) && !memcmp(next,"b2",2));
        persist(next); committed = 1;
        OK(syntra_managed_storage_complete(h,id,req.token,SYNTRA_STORAGE_DURABLE,NULL));
    }
    syntra_storage_request_free(&req);
    return committed;
}

static uint64_t start_upload(syntra_managed_t *h,uint64_t id,const syntra_manifest_t *m) {
    uint64_t t; int rc; int tries=0;
    do {rc=syntra_managed_upload(h,id,m,VIEW("large-source"),&t);
        if(++tries>5000) {syntra_lane_status_t s; OK(syntra_managed_status(h,id,2,&s)); fprintf(stderr,"cold admission stuck rc=%d state=%u\n",rc,s.state);assert(0);}
        if(rc==SYNTRA_BUSY || rc==SYNTRA_PENDING) tick();
    } while(rc==SYNTRA_BUSY || rc==SYNTRA_PENDING);
    OK(rc); return t;
}
static int32_t verify_large(uintptr_t ctx,const uint8_t *data,uintptr_t n) {
    size_t *offset=(size_t *)ctx;
    if (!*offset) {assert(n==262144); for(size_t i=0;i<n;i++) assert(data[i]=='a');}
    else assert(*offset==262144 && n==1 && *data=='z');
    *offset+=n; return 0;
}
static void resume_stage(syntra_managed_config_t c,const char *stage) {
    int successor = !strcmp(stage,"resume"); assert(successor || !strcmp(stage,"partial"));
    c.credential = successor ? VIEW("updates-new") : VIEW("updates-old");
    struct app app={.successor=successor};
    syntra_updates_t u={VIEW("acct"),VIEW("feed"),VIEW("feed"),(uintptr_t)&app,restore,apply_delta};
    syntra_manifest_t m={.version=1,.length=262145,.transfer_id={5},.sha256={
        0x1c,0xe3,0x55,0x22,0x43,0xf8,0xff,0xc7,0xbd,0x5e,0x4f,0x91,0xfa,0x89,0x04,0x7b,
        0xa9,0x0a,0xc0,0xde,0x9b,0xdb,0x90,0xb0,0xfb,0x70,0x98,0xa8,0x07,0x94,0xeb,0x9f}};
    memset(m.object,7,sizeof m.object);
    if (!successor) {
        persist((const uint8_t *)"a1");
        FILE *f=fopen("large-source","wb"); assert(f);
        for(size_t i=0;i<262144;i++) assert(fputc('a',f)=='a');
        assert(fputc('z',f)=='z' && !fclose(f));
    }
    syntra_managed_t *h; uint64_t id;
    OK(syntra_managed_open_updates(1,&c,&u,&h,&id));
    fprintf(stderr,"%s: waiting for restoration\n",stage);
    syntra_update_status_t status; int tries=0;
    do {assert(!storage(h,id)); OK(syntra_managed_update_status(h,id,&status));
        if(++tries>5000) {syntra_lane_status_t s; OK(syntra_managed_status(h,id,1,&s)); fprintf(stderr,"restore stuck state=%u lane=%u loaded=%d\n",status.state,s.state,atomic_load(&app.restored));assert(0);}
        assert(status.state!=SYNTRA_UPDATES_FAILED); if(status.state!=SYNTRA_UPDATES_RESTORED) tick();
    } while(status.state!=SYNTRA_UPDATES_RESTORED);
    assert(status.generation==ready(h,id,1) && atomic_load(&app.restored) && !atomic_load(&app.applied));
    uint64_t upload=start_upload(h,id,&m), t;
    fprintf(stderr,"%s: upload admitted\n",stage);
    syntra_managed_result_t r;
    if (!successor) {
        while(!storage(h,id)) {int rc=syntra_managed_poll(h,id,upload,&r);
            if(rc!=SYNTRA_PENDING) fprintf(stderr,"upload ended before update: %d/%d\n",rc,r.grpc_code);
            assert(rc==SYNTRA_PENDING); tick();} /* host only publishes after first Put commits */
        fputs("partial: durable update applied\n",stderr);
        assert(atomic_load(&app.applied)==1 && syntra_managed_poll(h,id,upload,&r)==SYNTRA_PENDING);
        uint64_t bulk[5];
        for(size_t i=0;i<5;i++) {
            syntra_view_t method=i ? VIEW("/fixture.Echo/Echo") : VIEW("/fixture.Echo/RawWait");
            int rc; do {rc=syntra_managed_call(h,id,2,method,VIEW("bulk"),5000,&bulk[i]); if(rc==SYNTRA_BUSY) tick();} while(rc==SYNTRA_BUSY);
            OK(rc);
        }
        OK(syntra_managed_cancel(h,id,bulk[0]));
        assert(syntra_managed_poll(h,id,bulk[0],&r)==SYNTRA_PENDING);
        assert(syntra_managed_call(h,id,2,VIEW("/fixture.Echo/Echo"),VIEW(""),5000,&t)==SYNTRA_BUSY && !t);
        OK(syntra_managed_call(h,id,1,VIEW("/fixture.Echo/Held"),VIEW("interactive"),2000,&t));
        r=take(h,id,t); assert(!r.grpc_code && r.generation==status.generation && r.data.len==11 && !memcmp(r.data.data,"interactive",11));
        syntra_free(r.data.data,r.data.len);
        for(size_t i=0;i<5;i++) {r=take(h,id,bulk[i]);assert(r.grpc_code==(i ? 0 : 1));syntra_free(r.data.data,r.data.len);}
        assert(syntra_managed_poll(h,id,upload,&r)==SYNTRA_PENDING);
        OK(syntra_managed_cancel(h,id,upload)); r=take(h,id,upload); assert(r.grpc_code==1);
    } else {
        r=take(h,id,upload); assert(!r.grpc_code);
        size_t verified=0;
        OK(syntra_managed_download(h,id,&m,VIEW("resumed.db"),VIEW("authority/account"),
            (syntra_sink_t){(uintptr_t)&verified,verify_large},&t));
        r=take(h,id,t); assert(!r.grpc_code && verified==m.length && !atomic_load(&app.applied));
    }
    close_owner(h,id);
    fprintf(stderr,"%s: owner closed\n",stage);
    if (successor) {
        /* A new authenticated connection cannot be restored without its LOAD.
         * Even after shutdown, C still owns that receipt until work stops. */
        OK(syntra_managed_open_updates(1,&c,&u,&h,&id));
        syntra_storage_request_t req; int rc;
        do {rc=syntra_managed_storage_take(h,id,&req); if(rc==SYNTRA_PENDING) tick();} while(rc==SYNTRA_PENDING);
        OK(rc); assert(req.kind==SYNTRA_STORAGE_LOAD);
        fputs("resume: load retained\n",stderr);
        OK(syntra_managed_update_status(h,id,&status)); assert(status.state==SYNTRA_UPDATES_RESTORING);
        OK(syntra_managed_shutdown(h,id));
        assert(syntra_managed_shutdown_poll(h,id)==SYNTRA_SHUTDOWN_INCOMPLETE);
        assert(syntra_managed_destroy(h,id)==SYNTRA_SHUTDOWN_INCOMPLETE);
        assert(syntra_managed_storage_complete(h,id,req.token,SYNTRA_STORAGE_UNAVAILABLE,NULL)==SYNTRA_STALE);
        syntra_storage_request_free(&req); close_owner(h,id);
    }
}
