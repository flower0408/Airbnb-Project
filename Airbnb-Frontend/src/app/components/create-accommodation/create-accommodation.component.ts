import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Accommodation } from 'src/app/models/accommodation.model';
import { User } from 'src/app/models/user.model';
import { AccommodationService } from 'src/app/services/accommodation.service';
import { UserService } from 'src/app/services/user.service';

@Component({
  selector: 'app-create-accommodation',
  templateUrl: './create-accommodation.component.html',
  styleUrls: ['./create-accommodation.component.css']
})
export class CreateAccommodationComponent implements OnInit {

  accommodationForm: FormGroup;

  constructor(private fb: FormBuilder,private accommodationService: AccommodationService,private userService:UserService) {

    this.accommodationForm = this.fb.group({
      name: [null, Validators.required],
      description: [null, Validators.required],
      images: [null, Validators.required],
      benefits: [null, Validators.required],
      Minguest: [null, Validators.required],
      Maxguest: [null, Validators.required],
      country: [null, Validators.required],
      city: [null, Validators.required],
      street: [null, Validators.required],
      number: [null, Validators.required]
    });

  }

  ngOnInit(): void {
  }

  onSubmit(){
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
