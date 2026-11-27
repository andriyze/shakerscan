export function createSseDecoder(onEvent:(name:string,value:Record<string,unknown>)=>void):{push(value:string):void;finish():void}
