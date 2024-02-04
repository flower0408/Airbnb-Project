export class RecoverPasswordDTO{
    id: string = "";
    new_password: string = "";
    repeated_new: string = "";

    RecoverPasswordDTO(id: string, new_password: string, repeated_new: string){
        this.id = id;
        this.new_password = new_password;
        this.repeated_new = repeated_new;
    }
}