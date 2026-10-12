// @category Tartarus
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class TartarusXrefs extends GhidraScript {
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
        ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(target.getEntryPoint());
        while (references.hasNext()) {
            Reference reference = references.next();
            println(reference.getFromAddress() + "\t" + reference.getReferenceType());
        }
    }
}
