import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Accommodation } from 'src/app/models/accommodation.model';
import { User } from 'src/app/models/user.model';
import { AccommodationService } from 'src/app/services/accommodation.service';
import { UserService } from 'src/app/services/user.service';
import { UpperLetterValidator } from 'src/app/services/customValidators';
import { MaxGuestValidator } from 'src/app/services/customValidators';

@Component({
  selector: 'app-create-accommodation',
  templateUrl: './create-accommodation.component.html',
  styleUrls: ['./create-accommodation.component.css']
})
export class CreateAccommodationComponent implements OnInit {

  accommodationForm!: FormGroup;

  constructor(private fb: FormBuilder,private accommodationService: AccommodationService,private userService:UserService) {
  }

  get f(): { [key: string]: AbstractControl } {
    return this.accommodationForm.controls;
  }

  ngOnInit(): void {

   this.accommodationForm = this.fb.group({
     name: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(35), Validators.pattern(/^[a-zA-Z0-9\s,'-]{3,35}$/)]],
     description: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(200), Validators.pattern(/^[a-zA-Z0-9\s,'-]{3,200}$/)]],
     images: ['', [Validators.required,Validators.pattern(/^[a-zA-Z0-9\s,'-]{3,200}$/)]],
     benefits: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(100), Validators.pattern(/^[a-zA-Z0-9\s,'-]{3,100}$/)]],
     Minguest: ['', [Validators.required, Validators.min(1)]],
     Maxguest: ['', [Validators.required,Validators.min(1), MaxGuestValidator(/*this.accommodationForm.get('Minguest')*/)]],
     country: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(35),UpperLetterValidator(), Validators.pattern(/^[A-Z][a-zA-Z\s-]{2,35}$/)]],
     city: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(35),UpperLetterValidator(), Validators.pattern(/^[A-Z][a-zA-Z\s-]{2,35}$/)]],
     street: ['', [Validators.required, Validators.minLength(2), Validators.maxLength(35),UpperLetterValidator(), Validators.pattern(/^[A-Z][a-zA-Z0-9\s,'-]{2,35}$/)]],
     number: ['', [Validators.required, Validators.min(1)]]
   });


  }

  submitted = false;

  onSubmit(){
    this.submitted = true;

    if (this.accommodationForm.valid) {

      const formValues = this.accommodationForm.value;

      const newAccommodation: Accommodation = {
        name: formValues.name,
        description: formValues.description,
        images: formValues.images,
        location: {
          country: formValues.country,
          city: formValues.city,
          street: formValues.street,
          number: formValues.number
        },
        benefits: formValues.benefits,
        minGuest: formValues.Minguest,
        maxGuest: formValues.Maxguest,
        ownerId: ""
      };


      this.userService.getUser().subscribe(
        (user: User) => {
          newAccommodation.ownerId = user.id

          this.accommodationService.createAccommodation(newAccommodation).subscribe(
            () => {
              console.log('Accommodation created successfully!');
              //this.toastr.success('Accommodation created successfully!');

            },
            (error) => {
              console.error('Error creating accommodation:', error);
              //this.toastr.error('Error creating accommodation!');
            }
          );

        },
        (error) => {
          console.error('Error get user data:', error);
        }
      );

    }
  }

}
