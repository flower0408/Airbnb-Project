import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RecoveryEnterTokenComponent } from './recovery-enter-token.component';

describe('RecoveryEnterTokenComponent', () => {
  let component: RecoveryEnterTokenComponent;
  let fixture: ComponentFixture<RecoveryEnterTokenComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ RecoveryEnterTokenComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(RecoveryEnterTokenComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
