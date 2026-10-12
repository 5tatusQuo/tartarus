// @category Tartarus
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class TartarusFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (functions.hasNext() && count++ < 10000) {
            Function function = functions.next();
            String name = function.getName().replace("\t", " ").replace("\n", " ");
            println("TARTARUS\t" + function.getEntryPoint() + "\t" + name);
        }
    }
}
