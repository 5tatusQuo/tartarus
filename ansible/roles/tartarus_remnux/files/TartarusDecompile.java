// @category Tartarus
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class TartarusDecompile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("one function name required");
        Function target = null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (function.getName().equals(args[0])) { target = function; break; }
        }
        if (target == null) throw new IllegalArgumentException("function not found");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults result = decompiler.decompileFunction(target, 30, monitor);
        if (!result.decompileCompleted()) throw new IllegalStateException("decompilation failed");
        println(result.getDecompiledFunction().getC());
        decompiler.dispose();
    }
}
