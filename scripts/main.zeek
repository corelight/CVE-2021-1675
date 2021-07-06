module PrintNightmare;

redef enum Notice::Type += {
    Printer_Driver_Changed_Successfully
};

export {
    const opnames: set[string] = {"RpcAddPrinterDriverEx", "RpcAddPrinterDriver", "RpcAsyncAddPrinterDriver"};
    }

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
    {
    if (!c$dce_rpc_state?$uuid)
        {
        return;
        }
    local opname = DCE_RPC::operations[c$dce_rpc_state$uuid, opnum];
    if (opname in opnames)
        {
        NOTICE([$note=Printer_Driver_Changed_Successfully, $msg="Possible CVE-2021-1675 (PrintNightmare) Exploit", $sub=(fmt("DCE_RPC opname = %s", opname)), $id=c$id, $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    }
