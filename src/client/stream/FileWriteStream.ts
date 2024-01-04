import { Writable } from "stream";
import File from "../File"

export type FileWriter = (offset: number, buffer: Buffer) => Promise<void>;

export class FileWriteStream extends Writable {
    private maxWriteChunkLength: number;
    private fileWriter: FileWriter;
    private _bytesWritten: number;

    get bytesWritten() {
        return this._bytesWritten;
    }

    constructor(maxWriteChunkLength: number, fileWriter: FileWriter) {
        super();
        this.maxWriteChunkLength = maxWriteChunkLength;
        this.fileWriter = fileWriter;
        this._bytesWritten = 0;
    }

    _write(chunk: Buffer, encoding, callback) {
        const chunkSize = chunk.length
        if (chunkSize > this.maxWriteChunkLength) {
            
        } else {
            this.fileWriter(this._bytesWritten, chunk)
            .then(() => {
                this._bytesWritten += chunkSize;
                callback();
            })
            .catch(callback);
        }
    }
}